/*
 * Copyright (C) 2015  Mozilla Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sdpsrvc.h"

/*
 * UUID numbers and service names are available at
 *
 *  https://www.bluetooth.org/en-us/specification/assigned-numbers/service-discovery
 *
 */

const char*
lookup_service_name_by_uuid16(uint16_t uuid16, const char* errstr)
{
  /* Protocol identifiers */

  static const char* byte3_00_00_00[256] = {
    [0x01] = "SDP",
    [0x02] = "UDP",
    [0x03] = "RFCOMM",
    [0x04] = "TCP",
    [0x05] = "TCS-BIN",
    [0x06] = "TCS-AT",
    [0x07] = "ATT",
    [0x08] = "OBEX",
    [0x09] = "IP",
    [0x0a] = "FTP",
    [0x0c] = "HTTP",
    [0x0e] = "WSP",
    [0x0f] = "BNEP",
    [0x10] = "UPNP",
    [0x11] = "HIDP",
    [0x12] = "HardcopyControlChannel",
    [0x14] = "HardcopyDataChannel",
    [0x16] = "HardcopyNotification",
    [0x17] = "AVCTP",
    [0x19] = "AVDTP",
    [0x1b] = "CMTP",
    [0x1e] = "MCAPControlChannel",
    [0x1f] = "MCAPDataChannel"
  };

  static const char* byte3_00_00_01[256] = {
    [0x00] = "L2CAP"
  };

  static const char* byte3_00_00_10[256] = {
    [0x00] = "ServiceDiscoveryServerServiceClassID",
    [0x01] = "BrowseGroupDescriptorServiceClassID"
  };

  static const char* byte3_00_00_11[256] = {
    [0x01] = "SerialPort",
    [0x02] = "LANAccessUsingPPP",
    [0x03] = "DialupNetworking",
    [0x04] = "IrMCSync",
    [0x05] = "ObexObjectPush",
    [0x06] = "ObexFileTransfer",
    [0x07] = "IrMCSyncCommand",
    [0x08] = "Headset",
    [0x09] = "CordlessTelephony",
    [0x0a] = "AudioSource",
    [0x0b] = "AudioSink",
    [0x0c] = "A/V_RemoteControlTarget",
    [0x0d] = "AdvancedAudioDistribution",
    [0x0e] = "A/V_RemoteControl",
    [0x0f] = "A/V_RemoteControlController",
    [0x10] = "Intercom",
    [0x11] = "Fax",
    [0x12] = "Headset - Audio Gateway (AG)",
    [0x13] = "WAP",
    [0x14] = "WAP_CLIENT",
    [0x15] = "PANU",
    [0x16] = "NAP",
    [0x17] = "GN",
    [0x18] = "DirectPrinting",
    [0x19] = "ReferencePrinting",
    [0x1a] = "Basic Imaging Profile",
    [0x1b] = "ImagingResponder",
    [0x1c] = "ImagingAutomaticArchive",
    [0x1d] = "ImagingReferencedObjects",
    [0x1e] = "Handsfree",
    [0x1f] = "HandsfreeAudioGateway",
    [0x20] = "DirectPrintingReferenceObjectsService",
    [0x21] = "ReflectedUI",
    [0x22] = "BasicPrinting",
    [0x23] = "PrintingStatus",
    [0x24] = "HumanInterfaceDeviceService",
    [0x25] = "HardcopyCableReplacement",
    [0x26] = "HCR_Print",
    [0x27] = "HCR_Scan",
    [0x28] = "Common_ISDN_Access",
    [0x2d] = "SIM_Access",
    [0x2e] = "Phonebook Access - PCE",
    [0x2f] = "Phonebook Access - PSE",
    [0x30] = "Phonebook Access",
    [0x31] = "Headset - HS",
    [0x32] = "Message Access Server",
    [0x33] = "Message Notification Server",
    [0x34] = "Message Access Profile",
    [0x35] = "GNSS",
    [0x36] = "GNSS_Server",
    [0x37] = "3D Display",
    [0x38] = "3D Glasses",
    [0x39] = "3D Synchronization",
    [0x3a] = "MPS Profile UUID",
    [0x3b] = "MPS SC UUID",
    [0x3c] = "CTN Access Service",
    [0x3d] = "CTN Notification Service",
    [0x3e] = "CTN Profile"
  };

  static const char* byte3_00_00_12[256] = {
    [0x00] = "PnPInformation",
    [0x01] = "GenericNetworking",
    [0x02] = "GenericFileTransfer",
    [0x03] = "GenericAudio",
    [0x04] = "GenericTelephony",
    [0x05] = "UPNP_Service",
    [0x06] = "UPNP_IP_Service"
  };

  static const char* byte3_00_00_13[256] = {
    [0x00] = "ESDP_UPNP_IP_PAN",
    [0x01] = "ESDP_UPNP_IP_LAP",
    [0x02] = "ESDP_UPNP_L2CAP",
    [0x03] = "VideoSource",
    [0x04] = "VideoSink",
    [0x05] = "VideoDistribution"
  };

  static const char* byte3_00_00_14[256] = {
    [0x00] = "HDP",
    [0x01] = "HDP Source",
    [0x02] = "HDP Sink"
  };

  static const char** byte2_00_00[256] = {
    [0x00] = byte3_00_00_00,
    [0x01] = byte3_00_00_01,
    [0x10] = byte3_00_00_10,
    [0x11] = byte3_00_00_11,
    [0x12] = byte3_00_00_12,
    [0x13] = byte3_00_00_13,
    [0x14] = byte3_00_00_14
  };

  uint8_t byte2, byte3;

  /* Bytes 0 and 1 are always '0x00' in a UUID16, so we start at byte 2. */

  byte2 = uuid16 >> 8;
  byte3 = uuid16 & 0xff;

  if (!byte2_00_00[byte2] || !byte2_00_00[byte2][byte3]) {
    return errstr;
  }
  return byte2_00_00[byte2][byte3];
}
