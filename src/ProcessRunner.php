<?php

declare(strict_types=1);

namespace DnsManager;

use RuntimeException;

final class ProcessRunner
{
	public static function executable(string $value): string
	{
		$candidates = str_contains($value, '/') ? [$value] : array_map(
			static fn (string $directory): string => rtrim($directory, '/') . '/' . $value,
			array_filter(explode(PATH_SEPARATOR, getenv('PATH') ?: '/usr/bin:/bin'), static fn (string $directory): bool => $directory !== '' && $directory !== '.'),
		);
		foreach ($candidates as $candidate) {
			if (is_file($candidate) && is_executable($candidate)) {
				return realpath($candidate) ?: $candidate;
			}
		}
		throw new RuntimeException('Executable not found or not executable: ' . $value);
	}

	/** @param list<string> $arguments
	 * @return array{exit_code: int, stdout: string, stderr: string}
	 */
	public static function run(array $arguments, string $input, int $timeout): array
	{
		if (!function_exists('proc_open')) {
			throw new RuntimeException('PHP proc_open() is required and must not be disabled.');
		}
		$arguments[0] = self::executable($arguments[0]);
		$pipes = [];
		$process = @proc_open($arguments, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		if (!is_resource($process)) {
			throw new RuntimeException('Could not start: ' . basename($arguments[0]));
		}
		foreach ($pipes as $pipe) {
			stream_set_blocking($pipe, false);
		}
		$start = hrtime(true);
		$offset = 0;
		$output = [1 => '', 2 => ''];
		$exitCode = null;
		try {
			while (true) {
				if (isset($pipes[0]) && $offset === strlen($input)) {
					fclose($pipes[0]);
					unset($pipes[0]);
				}
				$status = proc_get_status($process);
				if (!$status['running'] && $status['exitcode'] >= 0 && $exitCode === null) {
					$exitCode = $status['exitcode'];
				}
				foreach ([1, 2] as $number) {
					if (!isset($pipes[$number])) {
						continue;
					}
					$chunk = stream_get_contents($pipes[$number], 65536);
					if ($chunk === false) {
						throw new RuntimeException('Could not read child-process output.');
					}
					$output[$number] .= $chunk;
					if (strlen($output[1]) + strlen($output[2]) > 2097152) {
						throw new RuntimeException('Child-process output exceeded 2 MiB.');
					}
					if (feof($pipes[$number])) {
						fclose($pipes[$number]);
						unset($pipes[$number]);
					}
				}
				if (!$status['running'] && !isset($pipes[1]) && !isset($pipes[2])) {
					break;
				}
				if ((hrtime(true) - $start) / 1000000000 >= $timeout) {
					throw new RuntimeException(basename($arguments[0]) . ' timed out after ' . $timeout . ' seconds; the remote outcome may be unknown.');
				}
				$read = [];
				foreach ([1, 2] as $number) {
					if (isset($pipes[$number])) {
						$read[] = $pipes[$number];
					}
				}
				$write = isset($pipes[0]) && $status['running'] ? [$pipes[0]] : [];
				$except = null;
				if ($read === [] && $write === []) {
					usleep(10000);
					continue;
				}
				$selected = @stream_select($read, $write, $except, 0, 100000);
				if ($selected === false) {
					throw new RuntimeException('Could not poll child-process streams.');
				}
				if ($write !== []) {
					$written = @fwrite($pipes[0], substr($input, $offset, 8192));
					if ($written === false) {
						throw new RuntimeException('Child process closed its input before receiving all commands.');
					}
					$offset += $written;
				}
			}
		} catch (\Throwable $error) {
			@proc_terminate($process, 15);
			$deadline = hrtime(true) + 250000000;
			while (proc_get_status($process)['running'] && hrtime(true) < $deadline) {
				usleep(10000);
			}
			if (proc_get_status($process)['running']) {
				@proc_terminate($process, 9);
			}
			throw $error;
		} finally {
			foreach ($pipes as $pipe) {
				if (is_resource($pipe)) {
					fclose($pipe);
				}
			}
			$closedCode = proc_close($process);
		}
		return ['exit_code' => $exitCode ?? $closedCode, 'stdout' => $output[1], 'stderr' => $output[2]];
	}
}
