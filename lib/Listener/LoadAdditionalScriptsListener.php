<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2019 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\ScienceMesh\Listener;

use OCA\ScienceMesh\AppInfo\ScienceMeshApp;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCA\Files\Event\LoadAdditionalScriptsEvent;
use Psr\Log\LoggerInterface;
use OCP\Util;

class LoadAdditionalScriptsListener implements IEventListener
{
  public function __construct(
    private LoggerInterface $logger
  ) {
  }

  public function handle(Event $event): void
  {
    $this->logger->debug('Adding additional scripts', ['app' => ScienceMeshApp::APP_ID]);
    if (!($event instanceof LoadAdditionalScriptsEvent)) {
      return;
    }
    Util::addScript('sciencemesh', 'settings');
    Util::addStyle('sciencemesh', 'style');
  }
}
