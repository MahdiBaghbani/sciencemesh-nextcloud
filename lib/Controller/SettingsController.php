<?php

namespace OCA\ScienceMesh\Controller;

use OCP\IRequest;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCA\ScienceMesh\AppConfig;
use OCA\ScienceMesh\RevaHttpClient;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Http\TextPlainResponse;
use OCP\AppFramework\Http;
use OCA\Sciencemesh\ServerConfig;
use OCP\IConfig;
use Psr\Log\LoggerInterface;
use OCP\DB\QueryBuilder\IQueryBuilder;

/**
 * Settings controller for the administration page
 */
class SettingsController extends Controller
{
  private LoggerInterface $logger;
  private IConfig $config;
  private ServerConfig $serverConfig;
  private string $userId;
  private IQueryBuilder $qb;

  const CATALOG_URL = "https://iop.sciencemesh.uni-muenster.de/iop/mentix/sitereg";

  /**
   * @param string $AppName - application name
   * @param IRequest $request - request object
   * @param IURLGenerator $urlGenerator - url generator service
   * @param IL10N $trans - l10n service
   * @param LoggerInterface $logger - logger
   * @param AppConfig $config - application configuration
   */
  public function __construct(
    $AppName,
    IRequest $request,
    LoggerInterface $logger,
    AppConfig $config,
    IConfig $sciencemeshConfig,
    IQueryBuilder $qb,
    string $userId
  ) {
    parent::__construct($AppName, $request);
    $this->serverConfig = new ServerConfig($sciencemeshConfig);
    $this->qb = $qb;

    $this->logger = $logger;
    $this->config = $config;
    $this->userId = $userId;
  }

  /**
   * Print config section
   * FIXME: https://github.com/pondersource/nc-sciencemesh/issues/215
   * Listing is OK, but changing these settings
   * should probably really require Nextcloud server admin permissions!
   * @NoAdminRequired
   * @NoCSRFRequired
   * @return TemplateResponse
   */
  public function index()
  {
    $data = $this->loadSettings();
    if (!$data) {
      // settings has not been set
      $data = [
        "apikey" => "",
        "sitename" => "",
        "siteurl" => "",
        "siteid" => "",
        "country" => "",
        "iopurl" => "",
        "numusers" => 0,
        "numfiles" => 0,
        "numstorage" => 0
      ];
    }
    return new TemplateResponse($this->appName, "settings", $data, "blank");
  }

  /**
   * Simply method that posts back the payload of the request
   * @NoAdminRequired
   */
  public function saveSettings($apikey, $sitename, $siteurl, $country, $iopurl, $numusers, $numfiles, $numstorage)
  {
    $siteid = null;

    if ($numusers == null) {
      $numusers = 0;
    }
    if ($numfiles == null) {
      $numfiles = 0;
    }
    if ($numstorage == null) {
      $numstorage = 0;
    }

    // submit settings to Mentix (if they are valid)
    if ($apikey !== "" && $sitename !== "" && $siteurl !== "" && $iopurl !== "") {
      try {
        $siteid = $this->submitSettings($apikey, $sitename, $siteurl, $country, $iopurl);
      } catch (\Exception $e) {
        return new DataResponse([
          'error' => $e->getMessage()
        ]);
      }
    }

    // store settings in DB
    $this->deleteSettings();
    try {
      $this->storeSettings($apikey, $sitename, $siteurl, $siteid, $country, $iopurl, $numusers, $numfiles, $numstorage);
    } catch (\Exception $e) {
      return new DataResponse([
        'error' => 'error storing settings: ' . $e->getMessage()
      ]);
    }

    return new DataResponse(["siteid" => $siteid]);
  }

  private function storeSettings($apikey, $sitename, $siteurl, $siteid, $country, $iopurl, $numusers, $numfiles, $numstorage)
  {
    $this->qb->insert('sciencemesh')
      ->setValue('apikey', $this->qb->createNamedParameter($apikey))
      ->setValue('sitename', $this->qb->createNamedParameter($sitename))
      ->setValue('siteurl', $this->qb->createNamedParameter($siteurl))
      ->setValue('siteid', $this->qb->createNamedParameter($siteid))
      ->setValue('country', $this->qb->createNamedParameter($country))
      ->setValue('iopurl', $this->qb->createNamedParameter($iopurl))
      ->setValue('numusers', $this->qb->createNamedParameter($numusers))
      ->setValue('numfiles', $this->qb->createNamedParameter($numfiles))
      ->setValue('numstorage', $this->qb->createNamedParameter($numstorage));
    $result = $this->qb->executeStatement();

    if (!$result) {
      $this->logger->error('sciencemesh database cound not be updated', ['app' => 'sciencemesh']);
      throw new \Exception('sciencemesh database cound not be updated');
    }
  }

  private function deleteSettings()
  {
    $this->qb->delete('sciencemesh');
    $this->qb->executeStatement();
  }

  private function loadSettings()
  {
    $this->qb->select('*')->from('sciencemesh');
    $result = $this->qb->executeQuery();
    $row = $result->fetch();
    $result->closeCursor();
    return $row;
  }

  private function submitSettings($apikey, $sitename, $siteurl, $country, $iopurl)
  {
    // fill out a data object as needed by Mentix
    $iopPath = parse_url($iopurl, PHP_URL_PATH);
    $data = json_encode([
      "name" => $sitename,
      "url" => $siteurl,
      "countryCode" => $country,
      "reva" => [
        "url" => $iopurl,
        "metricsPath" => rtrim($iopPath, "/") . "/metrics"
      ]
    ]);
    $url = self::CATALOG_URL . "?action=register&apiKey=" . urlencode($apikey);

    // use CURL to send the request to Mentix
    $curl = curl_init($url);
    curl_setopt($curl, CURLOPT_HEADER, false);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_HTTPHEADER, array("Content-type: application/json"));
    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
    $response = curl_exec($curl);
    $respData = json_decode($response, true);
    $status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    curl_close($curl);

    if ($status == 200) {
      return $respData["id"];
    } else {
      throw new \Exception($respData["error"]);
    }
  }

  /**
   * Get app settings
   *
   * @return array
   *
   * @NoAdminRequired
   * @PublicPage
   */
  public function GetSettings()
  {
    // TODO: implement
    // $result = [
    //   "formats" => $this->config->FormatsSetting(),
    //   "sameTab" => $this->config->GetSameTab(),
    //   "shareAttributesVersion" => $this->config->ShareAttributesVersion()
    // ];
    $result = [
      "formats" => [],
      "sameTab" => [],
      "shareAttributesVersion" => []
    ];
    return $result;
  }

  /**
   * Save sciencemesh settings
   *
   * @return array
   *
   * @NoAdminRequired
   * @PublicPage
   */
  public function SaveSciencemeshSettings()
  {
    $sciencemesh_iop_url = $this->request->getParam('sciencemesh_iop_url');
    $sciencemesh_shared_secret = $this->request->getParam('sciencemesh_shared_secret');

    $this->serverConfig->setIopUrl($sciencemesh_iop_url);
    $this->serverConfig->setRevaSharedSecret($sciencemesh_shared_secret);

    return new TextPlainResponse(true, Http::STATUS_OK);
  }

  /**
   * Check IOP URL connection
   *
   * @return array
   *
   * @NoAdminRequired
   * @PublicPage
   */

  public function checkConnectionSettings()
  {
    $revaHttpClient = new RevaHttpClient($this->config, false);
    $response_sciencemesh_iop_url = $revaHttpClient->ocmProvider($this->userId);
    return new TextPlainResponse($response_sciencemesh_iop_url);
  }
}
