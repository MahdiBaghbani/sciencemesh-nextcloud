<?php

namespace OCA\ScienceMesh\Controller;

use OCP\AppFramework\Http;
use OCP\AppFramework\Http\TextPlainResponse;
use OCP\AppFramework\Controller;

class ContactsController extends Controller {
  
    public function deleteContact() {
      error_log('contact '.$_POST['username'].' is deleted');
      return new TextPlainResponse(true, Http::STATUS_OK);
    }
}
