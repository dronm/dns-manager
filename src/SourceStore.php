<?php

declare(strict_types=1);

namespace DnsManager;

use RuntimeException;

final class SourceStore
{
	public readonly string $path;
	/** @var resource|null */
	private $lock = null;

	public function __construct(string $path, int $timeout)
	{
		if (is_link($path)) {
			throw new RuntimeException('The source file must not be a symbolic link.');
		}
		$realPath = realpath($path);
		if ($realPath === false || !is_file($realPath) || !is_readable($realPath)) {
			throw new RuntimeException('Cannot read source file: ' . $path);
		}
		$this->path = $realPath;
		$lockPath = $realPath . '.lock';
		if (is_link($lockPath)) {
			throw new RuntimeException('The lock file must not be a symbolic link.');
		}
		$lock = @fopen($lockPath, 'c');
		if ($lock === false) {
			throw new RuntimeException('Cannot create source lock; the source directory must be writable: ' . $lockPath);
		}
		$this->lock = $lock;
		$deadline = hrtime(true) + $timeout * 1000000000;
		do {
			if (flock($lock, LOCK_EX | LOCK_NB)) {
				return;
			}
			if (hrtime(true) >= $deadline) {
				break;
			}
			usleep(50000);
		} while (true);
		$this->close();
		throw new RuntimeException('Another dns-manager operation holds the source lock.');
	}

	public function read(): string
	{
		clearstatcache(true, $this->path);
		$stat = @lstat($this->path);
		if ($stat === false || ($stat['mode'] & 0170000) !== 0100000 || $stat['nlink'] !== 1) {
			throw new RuntimeException('Source must be a regular file with one hard link.');
		}
		if ($stat['size'] > 2097152) {
			throw new RuntimeException('Source file exceeds the supported 2 MiB limit.');
		}
		$contents = @file_get_contents($this->path);
		if ($contents === false) {
			throw new RuntimeException('Could not read source file.');
		}
		return $contents;
	}

	public function save(string $expected, string $contents): bool
	{
		if ($this->read() !== $expected) {
			throw new RuntimeException('Source changed outside this operation; no DNS update was sent. Retry after reviewing the file.');
		}
		if ($expected === $contents) {
			return false;
		}
		$stat = stat($this->path);
		if ($stat === false) {
			throw new RuntimeException('Could not inspect source permissions.');
		}
		$temporary = tempnam(dirname($this->path), '.dns-manager-');
		if ($temporary === false) {
			throw new RuntimeException('Could not create a temporary source file.');
		}
		$stream = null;
		try {
			$stream = @fopen($temporary, 'wb');
			if ($stream === false) {
				throw new RuntimeException('Could not open the temporary source file.');
			}
			$offset = 0;
			while ($offset < strlen($contents)) {
				$written = fwrite($stream, substr($contents, $offset));
				if ($written === false || $written === 0) {
					throw new RuntimeException('Could not write the complete source file.');
				}
				$offset += $written;
			}
			if (!fflush($stream) || !fsync($stream)) {
				throw new RuntimeException('Could not flush source data to disk.');
			}
			$current = fstat($stream);
			if ($current === false) {
				throw new RuntimeException('Could not inspect the temporary file.');
			}
			if ($current['uid'] !== $stat['uid'] && !@chown($temporary, $stat['uid'])) {
				throw new RuntimeException('Cannot preserve source ownership; run as the source-file owner.');
			}
			if ($current['gid'] !== $stat['gid'] && !@chgrp($temporary, $stat['gid'])) {
				throw new RuntimeException('Cannot preserve source group.');
			}
			if (!chmod($temporary, $stat['mode'] & 0777)) {
				throw new RuntimeException('Cannot preserve source permissions.');
			}
			fclose($stream);
			$stream = null;
			if ($this->read() !== $expected) {
				throw new RuntimeException('Source changed while preparing the replacement; no DNS update was sent.');
			}
			if (!rename($temporary, $this->path)) {
				throw new RuntimeException('Could not atomically replace the source file.');
			}
		} finally {
			if (is_resource($stream)) {
				fclose($stream);
			}
			if (is_file($temporary)) {
				unlink($temporary);
			}
		}
		return true;
	}

	public function close(): void
	{
		if (is_resource($this->lock)) {
			flock($this->lock, LOCK_UN);
			fclose($this->lock);
		}
		$this->lock = null;
	}

	public function __destruct()
	{
		$this->close();
	}
}
