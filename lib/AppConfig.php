<?php

namespace OCA\ScienceMesh;


use OCP\IAppConfig;
use OCP\IConfig;

/**
 * Application configuration
 *
 * @package OCA\ScienceMesh
 */
class AppConfig
{

  private string $appName;

  private IAppConfig $appConfig;
  private IConfig $config;


  /**
   * @param string $AppName - application name
   * @param IAppConfig $appConfig - appConfig
   * @param IConfig $config - config
   */
  public function __construct(
    $AppName,
    IAppConfig $appConfig
  ) {

    $this->appName = $AppName;

    $this->config = $appConfig;
  }

  // FIXME: This does not seem right, it is setting a system value, but getting an app value
  public function GetConfigValue($key)
  {
    return $this->config->getSystemValue($this->appName)[$key];
  }

  public function SetConfigValue(string $key, string $value)
  {
    $this->appConfig->setValueString($this->appName, $key, $value);
  }
}
