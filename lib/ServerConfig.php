<?php

namespace OCA\ScienceMesh;

use OCP\IAppConfig;

function random_str(
  int $length = 64,
  string $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
): string {
  if ($length < 1) {
    throw new \RangeException("Length must be a positive integer");
  }
  $pieces = [];
  $max = mb_strlen($keyspace, '8bit') - 1;
  for ($i = 0; $i < $length; ++$i) {
    $pieces[] = $keyspace[random_int(0, $max)];
  }
  return implode('', $pieces);
}

/**
 * @package OCA\ScienceMesh
 */
class ServerConfig
{

  private IAppConfig $config;

  /**
   * @param IAppConfig $config
   */
  public function __construct(IAppConfig $config)
  {
    $this->config = $config;
  }

  public function getApiKey()
  {
    return $this->config->getValueString('sciencemesh', 'apiKey');
  }
  public function getSiteName()
  {
    return $this->config->getValueString('sciencemesh', 'siteName');
  }
  public function getSiteUrl()
  {
    return $this->config->getValueString('sciencemesh', 'siteUrl');
  }
  public function getSiteId()
  {
    return $this->config->getValueString('sciencemesh', 'siteId');
  }
  public function getCountry()
  {
    return $this->config->getValueString('sciencemesh', 'country');
  }
  public function getIopUrl()
  {
    return $this->config->getValueString('sciencemesh', 'iopUrl');
  }
  public function getRevaLoopbackSecret()
  {
    $ret = $this->config->getValueString('sciencemesh', 'revaLoopbackSecret');
    if (!$ret) {
      $ret = random_str(32);
      $this->config->setValueString('sciencemesh', 'revaLoopbackSecret', $ret);
    }
    return $ret;
  }
  public function getRevaSharedSecret()
  {
    $ret = $this->config->getValueString('sciencemesh', 'revaSharedSecret');
    if (!$ret) {
      $ret = random_str(32);
      $this->config->setValueString('sciencemesh', 'revaSharedSecret', $ret);
    }
    return $ret;
  }
  public function setRevaSharedSecret($sharedSecret)
  {
    $this->config->setValueString('sciencemesh', 'revaSharedSecret', $sharedSecret);
  }
  public function getNumUsers()
  {
    return $this->config->getValueString('sciencemesh', 'numUsers');
  }
  public function getNumFiles()
  {
    return $this->config->getValueString('sciencemesh', 'numFiles');
  }
  public function getNumStorage()
  {
    return $this->config->getValueString('sciencemesh', 'numStorage');
  }

  public function setApiKey($apiKey)
  {
    $this->config->setValueString('sciencemesh', 'apiKey', $apiKey);
  }
  public function setSiteName($siteName)
  {
    $this->config->setValueString('sciencemesh', 'siteName', $siteName);
  }
  public function setSiteUrl($siteUrl)
  {
    $this->config->setValueString('sciencemesh', 'siteUrl', $siteUrl);
  }
  public function setSiteId($siteId)
  {
    $this->config->setValueString('sciencemesh', 'siteId', $siteId);
  }
  public function setCountry($country)
  {
    $this->config->setValueString('sciencemesh', 'country', $country);
  }
  public function setIopUrl($iopUrl)
  {
    $this->config->setValueString('sciencemesh', 'iopUrl', $iopUrl);
  }
  public function setNumUsers($numUsers)
  {
    $this->config->setValueString('sciencemesh', 'numUsers', $numUsers);
  }
  public function setNumFiles($numFiles)
  {
    $this->config->setValueString('sciencemesh', 'numFiles', $numFiles);
  }
  public function setNumStorage($numStorage)
  {
    $this->config->setValueString('sciencemesh', 'numStorage', $numStorage);
  }
}
