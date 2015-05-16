/*

  This file is part of Kismet

  Kismet is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  Kismet is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with Kismet; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
  extension created by Yaker Mahieddine


*/

#include "config.h"

#include <errno.h>

#include "globalregistry.h"
#include "alertracker.h"
#include "dumpfile_json.h"
#include "packetsource.h"
#include "packetsourcetracker.h"
#include "netracker.h"



Dumpfile_Json::Dumpfile_Json() {
  fprintf(stderr, "FATAL OOPS: Dumpfile_Json called with no globalreg\n");
  exit(1);
}




Dumpfile_Json::Dumpfile_Json(GlobalRegistry *in_globalreg) :
  Dumpfile(in_globalreg) {
  globalreg = in_globalreg;

  jsonfile = NULL;

  type = "json";
  logclass = "json";

  if (globalreg->netracker == NULL) {
    _MSG("Deprecated netracker core disabled, disabling json logfile.",
         MSGFLAG_INFO);
    // fprintf(stderr, "FATAL OOPS:  Netracker missing before Dumpfile_Nettxt\n");
    // exit(1);
    return;
  }

  if (globalreg->kismet_config == NULL) {
    fprintf(stderr, "FATAL OOPS:  Config file missing before Dumpfile_Json\n");
    exit(1);
  }

  if (globalreg->alertracker == NULL) {
    fprintf(stderr, "FATAL OOPS:  Alertacker missing before Dumpfile_Json\n");
    exit(1);
  }

  // Find the file name
  if ((fname = ProcessConfigOpt()) == "" ||
      globalreg->fatal_condition) {
    return;
  }

  if ((jsonfile = fopen(fname.c_str(), "w")) == NULL) {
    _MSG("Failed to open json log file '" + fname + "': " + strerror(errno),
         MSGFLAG_FATAL);
    globalreg->fatal_condition = 1;
    return;
  }

  globalreg->RegisterDumpFile(this);

  _MSG("Opened json log file '" + fname + "'", MSGFLAG_INFO);

}



Dumpfile_Json::~Dumpfile_Json() {
  // Close files
  if (jsonfile != NULL) {
    Flush();
  }

  jsonfile = NULL;

  if (export_filter != NULL)
    delete export_filter;
}


int Dumpfile_Json::Flush(){

  if (jsonfile != NULL)
    fclose(jsonfile);

  string tempname = fname + ".temp";
  if ((jsonfile = fopen(tempname.c_str(), "w")) == NULL) {
    _MSG("Failed to open temporary nettxt file for writing: " +
         string(strerror(errno)), MSGFLAG_ERROR);
    return -1;
  }


  // Get the tracked network and client->ap maps
  const map<mac_addr, Netracker::tracked_network *> tracknet =
    globalreg->netracker->FetchTrackedNets();

  // Get the alerts
  const vector<kis_alert_info *> *alerts =
    globalreg->alertracker->FetchBacklog();

  map<mac_addr, Netracker::tracked_network *>::const_iterator x,finalIte;
  map<mac_addr, Netracker::tracked_client *>::const_iterator y,iteClient;

  int netnum = 0;
  // Dump all the networks
  fprintf(jsonfile,"{\"Networks\" : [\n");
  finalIte = tracknet.end();
  finalIte--;
  for (x = tracknet.begin(); x != tracknet.end(); ++x) {
    netnum++;

    if (export_filter->RunFilter(x->second->bssid, mac_addr(0), mac_addr(0)))
      continue;

    Netracker::tracked_network *net = x->second;

    if (net->type == network_remove)
      continue;


    string ntype;
    switch (net->type) {
    case network_ap:
      ntype = "infrastructure";
      break;
    case network_adhoc:
      ntype = "ad-hoc";
      break;
    case network_probe:
      ntype = "probe";
      break;
    case network_data:
      ntype = "data";
      break;
    case network_turbocell:
      ntype = "turbocell";
      break;
    default:
      ntype = "unknown";
      break;
    }

    fprintf(jsonfile,"\n{\n\"Network\":%d,\n",netnum);
    fprintf(jsonfile,"\"details\" : {\n");
    fprintf(jsonfile, "\"Manuf\"      : \"%s\",\n", net->manuf.c_str());
    fprintf(jsonfile, "\"First\"      : \"%.24s\",\n", ctime(&(net->first_time)));
    fprintf(jsonfile, "\"Last\"       : \"%.24s\",\n", ctime(&(net->last_time)));
    fprintf(jsonfile, "\"Type\"       : \"%s\",\n", ntype.c_str());
    fprintf(jsonfile, "\"BSSID_MAC\"      : \"%s\",\n", net->bssid.Mac2String().c_str());

    int ssidnum = 1;
    int count_ssid=0;
    fprintf(jsonfile,"\"BSSID_details\":{\n");
    for (map<uint32_t, Netracker::adv_ssid_data *>::iterator m  =
           net->ssid_map.begin(); m != net->ssid_map.end(); ++m) {
      count_ssid++;
    }
    for (map<uint32_t, Netracker::adv_ssid_data *>::iterator m  =
           net->ssid_map.begin(); m != net->ssid_map.end(); ++m) {

      fprintf(jsonfile,"\"SSID_Num\":%d,\n",ssidnum);
      fprintf(jsonfile,"\"SSID_Info\":{\n");
      string typestr;
      switch(m->second->type){
      case ssid_beacon:
        typestr = "Beacon";
        break;
      case ssid_proberesp:
        typestr = "Probe Response";
        break;
      case ssid_probereq:
        typestr = "Probe Request";
        break;
      case ssid_file:
        typestr = ssid_file;
        break;
      default:
        break;
      }
      fprintf(jsonfile, "\"Type\": \"%s\",\n", typestr.c_str());
      fprintf(jsonfile, "\"SSID\": \"%s %s\" ,\n", m->second->ssid.c_str(),
              m->second->ssid_cloaked ? "(Cloaked)" : "");

      if (m->second->beacon_info.length() > 0)
        fprintf(jsonfile, "    \"Info\"       : \"%s\",\n", 
                m->second->beacon_info.c_str());
      fprintf(jsonfile, "    \"First\"      : \"%.24s\",\n", 
              ctime(&(m->second->first_time)));
      fprintf(jsonfile, "    \"Last\"       : \"%.24s\",\n", 
              ctime(&(m->second->last_time)));
      fprintf(jsonfile, "    \"Max_Rate\"   : %2.1f,\n", m->second->maxrate);
      if (m->second->beaconrate != 0)
        fprintf(jsonfile, "    \"Beacon\"     : %d,\n", m->second->beaconrate);
      fprintf(jsonfile, "    \"Packets\"    : %d,\n", m->second->packets);

      if (m->second->dot11d_vec.size() > 0) {
        fprintf(jsonfile, "    \"Country\"    : \"%s\",\n", 
                m->second->dot11d_country.c_str());
      }
      fprintf(jsonfile,"\"Encryption\" : [");

      int i,cpt;
      int listeCrypt[20];

      for(i = 0;i<20;i++)
        listeCrypt[i] = 0;

      cpt = 0;
      i = 0;
      if (m->second->cryptset == 0){
        // fprintf(jsonfile, "  \"None\"");
        listeCrypt[i] = 1;
        cpt++;
      }
      i++;
      if (m->second->cryptset == crypt_wep){
        //fprintf(jsonfile, "  \"WEP\"");

        listeCrypt[i] = 1;
        cpt++;
      }
      i++;
      if (m->second->cryptset & crypt_layer3){
        //fprintf(jsonfile, "    \"Layer3\"");

        listeCrypt[i] = 1;
        cpt++;
      }
      i++;
      if (m->second->cryptset & crypt_wpa_migmode){
        //fprintf(jsonfile, "    \"WPA Migration Mode\"");

        listeCrypt[i] = 1;
        cpt++;
      }
      i++;
      if (m->second->cryptset & crypt_wep40){
        //fprintf(jsonfile, "   \"WEP40\"");

        listeCrypt[i] = 1;
        cpt++;
      }
      i++;
      if (m->second->cryptset & crypt_wep104){
        //fprintf(jsonfile, "    \"WEP104\"");

        listeCrypt[i] = 1;
        cpt++;
      }
      /*
        if (m->second->cryptset & crypt_wpa)
        fprintf(jsonfile, "    Encryption : WPA\n");
      */

      i++;
      if (m->second->cryptset & crypt_psk){
        //fprintf(jsonfile, "    \"WPA+PSK\"");

        listeCrypt[i] = 1;
        cpt++;
      }
      i++;

      if (m->second->cryptset & crypt_tkip){
        //fprintf(jsonfile, "    \"WPA+TKIP\"");

        listeCrypt[i] = 1;
        cpt++;
      }
      i++;
      if (m->second->cryptset & crypt_aes_ocb){
        //fprintf(jsonfile, "    \"WPA+AES-OCB\"");

        listeCrypt[i] = 1;
        cpt++;
      }
      i++;
      if (m->second->cryptset & crypt_aes_ccm){
        //fprintf(jsonfile, "    \"WPA+AES-CCM\"");

        listeCrypt[i] = 1;
        cpt++;
      }
      i++;
      if (m->second->cryptset & crypt_leap){
        //fprintf(jsonfile, "    \"WPA+LEAP\"");

        listeCrypt[i] = 1;
        cpt++;
      }
      i++; 

      if (m->second->cryptset & crypt_ttls){
        //fprintf(jsonfile, "    \"WPA+TTLS\"");
        listeCrypt[i] = 1;
        cpt++;
      }
      i++;
      if (m->second->cryptset & crypt_tls){
        //fprintf(jsonfile, "    \"WPA+TLS\"");

        listeCrypt[i] = 1;
        cpt++;
      }
      i++;
      if (m->second->cryptset & crypt_peap){
        //fprintf(jsonfile, "    \"WPA+PEAP\"");

        listeCrypt[i] = 1;
        cpt++;
      }
      i++;
      if (m->second->cryptset & crypt_isakmp){
        //fprintf(jsonfile, "    \"ISAKMP\"");

        listeCrypt[i] = 1;
        cpt++;
      }
      i++;
      if (m->second->cryptset & crypt_pptp){
        //fprintf(jsonfile, "    \"PPTP\"");

        listeCrypt[i] = 1;
        cpt++;
      }
      i++;
      if (m->second->cryptset & crypt_fortress){
        //fprintf(jsonfile, "    \"Fortress\"");

        listeCrypt[i] = 1;
        cpt++;
      }
      i++;
      if (m->second->cryptset & crypt_keyguard){
        //fprintf(jsonfile, "    \"Keyguard\"");

        listeCrypt[i] = 1;
        cpt++;
      }
      cpt++;
      int j;

      for(j=0;j<i;j++){
        switch(j){
        case 0:
          if(listeCrypt[j]){
            fprintf(jsonfile, "  \"None\"");
            cpt--;
          }
          break;
        case 1:
          if(listeCrypt[j]){
            fprintf(jsonfile, "  \"WEP\"");
            cpt--;
          }
          break;
        case 2:
          if(listeCrypt[j]){
            fprintf(jsonfile, "    \"Layer3\"");
            cpt--;
          }
          break;
        case 3:
          if(listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA Migration Mode\"");
            cpt--;
          }
          break;
        case 4:
          if (listeCrypt[j] ){
            fprintf(jsonfile, "    \"WPA Migration Mode\"");
            cpt--;
          }
          break;
        case 5:
          if (listeCrypt[j]){
            fprintf(jsonfile, "   \"WEP40\"");
            cpt--;
          }

          break;
        case 6:
          if (listeCrypt[j]){
            fprintf(jsonfile, "   \"WEP40\"");
            cpt--;
          }
          break;
        case 7:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WEP104\"");
            cpt--;
          }
          break;
        case 8:

          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA+PSK\"");
            cpt--;
          }
          break;
        case 9:

          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA+TKIP\"");
            cpt--;
          }
          break;
        case 10:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA+AES-OCB\"");
            cpt--;
          }
        case 11:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA+AES-CCM\"");
            cpt--;
          }
          break;
        case 12:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA+LEAP\"");
            cpt--;
          }
        case 13:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA+TTLS\"");
            cpt--;
          }
          break;
        case 14:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA+TLS\"");
            cpt--;
          }
          break;
        case 15:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"WPA+PEAP\"");
            cpt--;
          }
        case 16:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"ISAKMP\"");
            cpt--;
          }
          break;
        case 17:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"PPTP\"");
            cpt--;
          }
          break;
        case 18:
          if (listeCrypt[j] ){
            fprintf(jsonfile, "    \"Fortress\"");
            cpt--;
          }
          break;
        case 19:
          if (listeCrypt[j]){
            fprintf(jsonfile, "    \"Keyguard\"");
            cpt--;
          }
          break;
        default:
          break;
        }
        if((cpt > 1) & (listeCrypt[j]) ){
          fprintf(jsonfile, ",");

        }
      }
      fprintf(jsonfile, " ]\n");
      fprintf(jsonfile,"}");
      if(ssidnum < count_ssid)
        fprintf(jsonfile,",\n");
      else
        fprintf(jsonfile,"\n");
      ssidnum++;

    }
    fprintf(jsonfile,"},\n");
    fprintf(jsonfile, " \"Max Seen\"   : %d,\n", net->snrdata.maxseenrate * 100);

    int listeCarrier[8];
    int i,cpt;
    for(i=0;i<8;i++)
      listeCarrier[i]=0;


    fprintf(jsonfile, " \"Carrier\"    : [");
    cpt = i = 0;
    if (net->snrdata.carrierset & (1 << (int) carrier_80211b))
      {
        cpt++;
        listeCarrier[i] = 1;
      }
    i++;

    if (net->snrdata.carrierset & (1 << (int) carrier_80211bplus))
      {
        cpt++;
        listeCarrier[i] = 1;
      }
    i++;

    if (net->snrdata.carrierset & (1 << (int) carrier_80211a))
      {
        cpt++;
        listeCarrier[i] = 1;
      }
    i++;

    if (net->snrdata.carrierset & (1 << (int) carrier_80211g))
      {
        cpt++;
        listeCarrier[i] = 1;
      }
    i++;
    if (net->snrdata.carrierset & (1 << (int) carrier_80211fhss))
      {
        cpt++;
        listeCarrier[i] = 1;
      }
    i++;
    if (net->snrdata.carrierset & (1 << (int) carrier_80211dsss))
      {
        cpt++;
        listeCarrier[i] = 1;
      }
    i++;
    if (net->snrdata.carrierset & (1 << (int) carrier_80211n20))
      {
        cpt++;
        listeCarrier[i] = 1;
      }
    i++;
    if (net->snrdata.carrierset & (1 << (int) carrier_80211n40))
      {
        cpt++;
        listeCarrier[i] = 1;
      }
    i++;
    cpt++;
    int j;

    for(j=0;j<i;j++){
      switch(j){
      case 0:
        if (listeCarrier[j]){
          fprintf(jsonfile, " \"IEEE 802.11b\"");
          cpt--;
        }
        break;
      case 1:
        if (listeCarrier[j]){
          fprintf(jsonfile, " \"IEEE 802.11b+\"");
          cpt--;
        }
        break;
      case 2:
        if (listeCarrier[j]){
          fprintf(jsonfile, " \"IEEE 802.11a\"");
          cpt--;
        }
        break;
      case 3:
        if (listeCarrier[j]){
          fprintf(jsonfile, " \"IEEE 802.11g\"");
          cpt--;
        }
        break;
      case 4:
        if (listeCarrier[j]){
          fprintf(jsonfile, " \"IEEE 802.11 FHSS\"");
          cpt--;
        }
        break;
      case 5:
        if (listeCarrier[j]){
          fprintf(jsonfile, " \"IEEE 802.11 DSSS\"");
          cpt--;
        }
        break;
      case 6:
        if( listeCarrier[j]){
          fprintf(jsonfile, " \"IEEE 802.11n 20MHz\"");
          cpt--;
        }
        break;
      case 7:
        if( listeCarrier[j]){
          fprintf(jsonfile, " \"IEEE 802.11n 40MHz\"");
          cpt--;
        }
        break;
      }
      if((cpt > 1) & listeCarrier[j])
        fprintf(jsonfile, ",");
    }
    fprintf(jsonfile, " ],\n");

    int listeEnco[5];
    for(i=0;i<5;i++)
      listeEnco[i] = 0;


    i = 0;
    cpt = 0;
    if (net->snrdata.encodingset & (1 << (int) encoding_cck)){
      cpt++;
      listeEnco[i] = 1;
    }
    i++;
    if (net->snrdata.encodingset & (1 << (int) encoding_pbcc)){
      cpt++;
      listeEnco[i] = 1;
    }
    i++;
    if (net->snrdata.encodingset & (1 << (int) encoding_ofdm)){
      cpt++;
      listeEnco[i] = 1;
    }
    i++;
    if (net->snrdata.encodingset & (1 << (int) encoding_dynamiccck)){
      cpt++;
      listeEnco[i] = 1;
    }
    i++;
    if (net->snrdata.encodingset & (1 << (int) encoding_gfsk)){
      cpt++;
      listeEnco[i] = 1;

    }
    i++;
    cpt++;
    fprintf(jsonfile, " \"Encoding\"    : [");

    for(j=0;j<i;j++){
      switch(j){
      case 0:
        if (listeEnco[j]){
          fprintf(jsonfile, " \"CCK\"");
          cpt--;
        }
        break;
      case 1:
        if(listeEnco[j]){
          fprintf(jsonfile, " \"PBCC\"");
          cpt--;
        }
        break;
      case 2:
        if(listeEnco[j]){
          fprintf(jsonfile, " \"OFDM\"");
          cpt--;
        }
        break;
      case 3:
        if(listeEnco[j]){
          fprintf(jsonfile, " \"Dynamic CCK-OFDM\"");
          cpt--;
        }
        break;
      case 4:
        if(listeEnco[j]){
          fprintf(jsonfile, " \"GFSK\"");
          cpt--;
        }
        break;
      }
      if((cpt > 1) & listeEnco[j])
        fprintf(jsonfile,",");

    }
    fprintf(jsonfile, " ],\n");



    if (net->snrdata.last_signal_rssi != 0) {
      fprintf(jsonfile, " \"signal_rssi\":%d,\n \"noise_rssi\":%d,\n",
              net->snrdata.last_signal_rssi, net->snrdata.last_noise_rssi);
    }
    if (net->snrdata.last_signal_dbm != 0) {
      fprintf(jsonfile, " \"signal_dbm\":%d, \n\"noise_dbm\":%d,\n",
              net->snrdata.last_signal_dbm, net->snrdata.last_noise_dbm);
    }

    fprintf(jsonfile, " \"Channel\"    : %d,\n", net->channel);
    fprintf(jsonfile, " \"LLC\"        : %d,\n", net->llc_packets);
    fprintf(jsonfile, " \"Data\"       : %d,\n", net->data_packets);
    fprintf(jsonfile, " \"Crypt\"      : %d,\n", net->crypt_packets);
    fprintf(jsonfile, " \"Fragments\"  : %d,\n", net->fragments);
    fprintf(jsonfile, " \"Retries\"    : %d,\n", net->retries);
    fprintf(jsonfile, " \"Total\"      : %d,\n", net->llc_packets + net->data_packets);
    fprintf(jsonfile, " \"Datasize\"   : %llu",
            (long long unsigned int) net->datasize);

    int virgule;
    virgule = 0;
    if (net->gpsdata.gps_valid) {
      virgule = 1;
      fprintf(jsonfile,",\n");
      fprintf(jsonfile,"\"Location\" : \"%f,%f\",\n",net->gpsdata.aggregate_lat,net->gpsdata.aggregate_lon);
      fprintf(jsonfile,"\"Altitude\" : %f,\n",net->gpsdata.aggregate_alt);

    }


    if (net->guess_ipdata.ip_type > ipdata_factoryguess && 
        net->guess_ipdata.ip_type < ipdata_group) {
      virgule = 1;
      string iptype;
      fprintf(jsonfile,",");
      switch (net->guess_ipdata.ip_type) {
      case ipdata_udptcp:
        iptype = "UDP/TCP";
        break;
      case ipdata_arp:
        iptype = "ARP";
        break;
      case ipdata_dhcp:
        iptype = "DHCP";
        break;
      default:
        iptype = "Unknown";
        break;
      }

      fprintf(jsonfile, " \"IP Type\"    : %s,\n", iptype.c_str());
      fprintf(jsonfile, " \"IP Block\"   : %s,\n", 
              inet_ntoa(net->guess_ipdata.ip_addr_block));
      fprintf(jsonfile, " \"IP Netmask\" : %s,\n", 
              inet_ntoa(net->guess_ipdata.ip_netmask));
      fprintf(jsonfile, " \"IP Gateway\" : %s,\n", 
              inet_ntoa(net->guess_ipdata.ip_gateway));

      fprintf(jsonfile, " \"Last BSSTS\" : %llu,\n", 
              (long long unsigned int) net->bss_timestamp);
    }



    if(!virgule)
      fprintf(jsonfile,",\n");

    fprintf(jsonfile,"\"Clients\" :[\n");

    int clinum = 0;
    int sizeClient = 0;
    for (y = net->client_map.begin(); y != net->client_map.end(); ++y)
      sizeClient++;
    iteClient = net->client_map.end();

    for (y = net->client_map.begin(); y != net->client_map.end(); ++y){
      Netracker::tracked_client *cli = y->second;
      clinum++;
      if (cli->type == client_remove)
        continue;
      string ctype;
      switch (cli->type) {
      case client_fromds:
        ctype = "From Distribution";
        break;
      case client_tods:
        ctype = "To Distribution";
        break;
      case client_interds:
        ctype = "Inter-Distribution";
        break;
      case client_established:
        ctype = "Established";
        break;
      case client_adhoc:
        ctype = "Ad-hoc";
        break;
      default:
        ctype = "Unknown";
        break;
      }
      fprintf(jsonfile, " {\"Client\""" : {\n");
      fprintf(jsonfile,"\"num\":%d,\n",clinum);
      fprintf(jsonfile, "  \"Manuf\"      : \"%s\",\n", cli->manuf.c_str());
      fprintf(jsonfile, "  \"First\"      : \"%.24s\",\n", ctime(&(cli->first_time)));
      fprintf(jsonfile, "  \"Last\"       : \"%.24s\",\n", ctime(&(cli->last_time)));
      fprintf(jsonfile, "  \"Type\"       : \"%s\",\n", ctype.c_str());
      fprintf(jsonfile, "  \"MAC\"        : \"%s\"\n", cli->mac.Mac2String().c_str());
      fprintf(jsonfile,"}\n}");
      if(clinum !=  sizeClient )
        fprintf(jsonfile,",\n");
      else
        fprintf(jsonfile,"\n");
    }


    fprintf(jsonfile,"]\n");


    fprintf(jsonfile,"}\n");


    fprintf(jsonfile,"}\n");
    if((x != finalIte) & (x != tracknet.end()))
      fprintf(jsonfile,",");
  }

  fprintf(jsonfile,"]\n}");



  fflush(jsonfile);

  fclose(jsonfile);

  jsonfile = NULL;

  if (rename(tempname.c_str(), fname.c_str()) < 0) {
    _MSG("Failed to rename nettxt temp file " + tempname + " to " + fname + ":" +
         string(strerror(errno)), MSGFLAG_ERROR);
    return -1;
  }

  dumped_frames = netnum;

  return 1;

}


