<?php

namespace OCA\ScienceMesh\AppInfo;

use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\Collaboration\Collaborators\ISearch;
use OCP\Share\IManager;
use OCP\Notification\IManager as NotificationManager;
use OCA\ScienceMesh\Plugins\ScienceMeshSearchPlugin;
use OCA\ScienceMesh\ShareProvider\ScienceMeshShareProvider;
use OCA\ScienceMesh\Notifier\ScienceMeshNotifier;

class ScienceMeshApp extends App implements IBootstrap
{
  public const APP_ID = 'sciencemesh';
  public const APP_NAME = 'ScienceMesh';
  public const SHARE_TYPE_REMOTE = 6;
  private ISearch $collaboration;
  private IManager $shareManager;
  private NotificationManager $notificationManager;

  public function __construct(
    ISearch $collaboration,
    IManager $shareManager,
    NotificationManager $notificationManager
  ) {
    parent::__construct(self::APP_ID);
    $this->collaboration = $collaboration;
    $this->shareManager = $shareManager;
    $this->notificationManager = $notificationManager;
  }
  public function register(IRegistrationContext $context): void
  {
    $context->registerService(
      'UserService',
      function ($c) {
        return new \OCA\ScienceMesh\Service\UserService(
          $c->query('UserSession')
        );
      }

    );

    $context->registerService('UserSession', function ($c) {
      return $c->query('ServerContainer')->getUserSession();
    });

    // currently logged in user, userId can be gotten by calling the
    // getUID() method on it
    $context->registerService('User', function ($c) {
      return $c->query('UserSession')->getUser();
    });

    $this->collaboration->registerPlugin(['shareType' => 'SHARE_TYPE_REMOTE', 'class' => ScienceMeshSearchPlugin::class]);

    $this->shareManager->registerShareProvider(ScienceMeshShareProvider::class);

    $this->notificationManager->registerApp(ScienceMeshNotifier::class);
  }
  public function boot(IBootContext $context): void
  {
  }
}
