#include <nfastapp.h>
#include <seelib.h>
#include <string.h>
#include <stdlib.h>

#include "module_certificate.h"
#include "log.h"
#include "memzero.h"

extern NFastApp_Connection conn;
extern NFast_AppHandle app;

/**
 * Loads code signing certificates for the working Security World on the nCipher
 * These are used to verify signatures on CodeSafe modules when they attempt to
 * access keys that are protected by a seeinteg key
 */
Result module_certificate_init(M_CertificateList *cert_list, M_Certificate *certs) {
  int signer_count = 0;
  M_Command command;
  M_Reply reply;
  M_Status retcode;

  memzero(&command, sizeof(command));
  memzero(&reply, sizeof(reply));

  command.cmd = Cmd_GetWorldSigners;

  retcode = NFastApp_Transact(conn, NULL, &command, &reply, NULL);
  if (retcode != Status_OK) {
    ERROR("NFastApp_Transact failed");
    return Result_NFAST_APP_TRANSACT_FAILURE;
  }

  if ((retcode = reply.status) != Status_OK) {
    ERROR("NFastApp_Transact failed");
    NFastApp_Free_Reply(app, NULL, NULL, &reply);
    return Result_NFAST_APP_TRANSACT_STATUS_FAILURE;
  }

  signer_count = reply.reply.getworldsigners.n_sigs;
  INFO("Got %d signers", signer_count);
  if (signer_count == 0) {
    NFastApp_Free_Reply(app, NULL, NULL, &reply);
    return Result_GET_MODULE_CERTIFICATE_NO_SIGNERS;
  }

  if (signer_count > SEE_CERT_SIGNER_SIZE) {
    NFastApp_Free_Reply(app, NULL, NULL, &reply);
    return Result_GET_MODULE_CERTIFICATE_TOO_MANY_SIGNERS;
  }

  cert_list->n_certs = signer_count;
  cert_list->certs = certs;

  int i;
  for (i = 0; i < signer_count; i++) {
    certs[i].type = CertType_SEECert;
    memcpy(&certs[i].keyhash,
           &(reply.reply.getworldsigners.sigs[i].hash),
           sizeof(M_KeyHash));
  }

  NFastApp_Free_Reply(app, NULL, NULL, &reply);
  return Result_SUCCESS;
}

void module_certificate_cleanup(M_CertificateList *cert_list) {
  int i;
  for (i = 0; i < cert_list->n_certs; i++) {
    memzero(&cert_list->certs[i], sizeof(M_Certificate));
  }

  memzero(cert_list, sizeof(M_CertificateList));
}