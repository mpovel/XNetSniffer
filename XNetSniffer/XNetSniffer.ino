#include <SimpleSyslog.h>
#include <ArduinoOTA.h>
#include <ESP8266WiFi.h>
#include <SoftwareSerial.h>

SoftwareSerial XNetSwSerial;

#define SYSLOG_SERVER   "192.168.178.105"
#define APPLICATION "ESP-XNetSniffer"

#define LOK_ADRESS(ah,al) ((ah<<8)|al)

SimpleSyslog syslog("ESP-XNetSniffer","XN-Sniff",SYSLOG_SERVER);

#define MAX_BUFFER 5   // Number of receive buffers
typedef struct t_XN_Telegram {
    uint8_t cData[17];
    uint8_t iTelegramLength;
} _t_XN_Telegram;

t_XN_Telegram Buffer[MAX_BUFFER] = {0};
int aktRec = 0;     // Actual receive Buffer used
int byteRec = 0;    // Actual receive byte position
int NrTelegram = 0;

const int MAX485_CONTROL = D0;  // Pin used for switch RX/TX on MAX485
const int MAX485_DATA = D6;     // Pin used for send receive on MAX485
#include <stdio.h>

#define CALL_BYTE 0
#define HEADER    1

char line[80];

char *DumpData(uint8_t *data,uint8_t size)
{
static char Buffer[60]="";
    unsigned char * pin = data;
    const char * hex = "0123456789ABCDEF";
    char * pout = Buffer;
    for(; pin < data+size; pout+=3, pin++){
        pout[0] = hex[(*pin>>4) & 0xF];
        pout[1] = hex[ *pin     & 0xF];
        pout[2] = ':';
    }
    pout[-1] = 0;
    return Buffer;
}

char *AnalyzeXNetPacket(char cData[])
{
uint8 iAdr = cData[CALL_BYTE] & 0x1F;
uint8 iLength = (cData[HEADER] & 0x0F) + 3; // XOR, Header and Callbye not coded
uint8 linePos = 4;
bool response = false;

    switch (cData[CALL_BYTE] & 0x60){
        case 0x00:
            // Response
            linePos = sprintf(line,"QU  %2d ",iAdr);
            break;
        case 0x20:
            // TBD
            syslog.printf(FAC_LOCAL7, PRI_ERROR, (char*)"XN: %s",DumpData(Buffer[aktRec].cData,Buffer[aktRec].iTelegramLength));

            linePos = sprintf(line,"TBD    ");
            break;
        case 0x40:
            // Request
            linePos = sprintf(line,"REQ %2d ",iAdr);
            break;
        case 0x60:
            // Broadcast
            if (iAdr == 0){
              linePos = sprintf(line,"BC     ");
            } else {
              linePos = sprintf(line,"RES %2d ",iAdr);
              response = true;
            }

            break;        
    }

    switch (cData[HEADER] & 0xF0){
        case 0x00: // Clock
            switch (cData[HEADER+1]){
                case 0x01: // Timecode transfer, accelerated layout time
                    sprintf(line+linePos,"Timecode transfer");
                    break;
                case 0xF1: // DCC FAST CLOCK set request.
                    sprintf(line+linePos,"Fast clock set");
                    break;
                case 0xF2: // DCC FAST CLOCK get request.
                    sprintf(line+linePos,"Fast clock get");
                    break;
                default: // Invalid
                    sprintf(line+linePos,"Invalid 0x%02X 0x%02X",(int)cData[HEADER],(int)cData[HEADER+1]);
                    break;
            }
            break;
        case 0x10: // DCC extended accessory command
            sprintf(line+linePos,"extended accessory command");
            break;
        case 0x20: // 
            switch (cData[HEADER+1]){
                case 0x10: // Request for Service Mode results
                    sprintf(line+linePos,"Request for Service Mode results");
                    break;
                case 0x11: // Register Mode read request
                    sprintf(line+linePos,"Register Mode read request 0x%02X",(int) cData[3]);
                    break;
                case 0x12: // Register Mode write request
                    sprintf(line+linePos,"Register Mode write request 0x%02X 0x%02X",cData[3],cData[4]);
                    break;
                case 0x14: // Paged Mode read request
                    break;
                case 0x15:
                    if (cData[HEADER] == 0x22){
                        // Direct Mode CV read request
                    } else {
                        // Direct Mode CV read request for Multimaus, Bank Mode
                    }
                    break;
                case 0x16:
                    if (cData[HEADER] == 0x23){
                        // Direct Mode CV write request
                    } else {
                        // Direct Mode CV write request for Multimaus
                    }
                    break;
                case 0x17: // Paged Mode write request
                    break;
                case 0x18: // Direct Mode CV read request (CV mode (CV1024, CV=1..255))
                    break;
                case 0x19: // Direct Mode CV read request (CV mode (CV=256 ... 511))
                    break;
                case 0x1A: // Direct Mode CV read request (CV mode (CV=512 ... 767))
                    break;
                case 0x1B: // Direct Mode CV read request (CV mode (CV=768 ... 1023))
                    break;
                case 0x1C: // Direct Mode CV write request (CV mode (CV1024, CV=1..255))
                    break;
                case 0x1D: // Direct Mode CV write request (CV mode (CV=256 ... 511))
                    break;
                case 0x1E: // Direct Mode CV write request (CV mode (CV=512 ... 767))
                    break;
                case 0x1F: // Direct Mode CV write request (CV mode (CV=768 ... 1023))
                    break;
                case 0x21: // Command station software-version request
                    break;
                case 0x22: // Set command station power-up mode
                    break;
                case 0x24: // Command station status request
                    break;
                case 0x28: // SO (special option) read request; this allows to read the internal configuration values.
                    break;
                case 0x29: // SO write request
                    break;
                case 0x80: // Stop operations request (emergency off)
                    break;
                case 0x81: // Resume operations request
                    break;
                default:    // Unknown 0x2x command
                    sprintf(line+linePos,"Unknown 0x%02X 0x%02X",(int)cData[HEADER],(int)cData[HEADER+1]);
                    break;                
            }
            break;
        case 0x30: // Command Tunnel
            break;
        case 0x40: // Accessory Decoder information request
            if (5 != iLength){
                // Invalid 
                sprintf(line+linePos,"Invalid 0x%02X 0x%02X",(int)cData[HEADER],(int)cData[HEADER+1]);
            } else {
              if (response){  // 2.15
                sprintf(line+linePos,"Switch %d %s 0x%02X",(int)cData[2]*4,(cData[3] & 0x80 == 0x80? "Busy":"Done"),(int)cData[3]);
                // syslog.printf(FAC_LOCAL7, PRI_ERROR, (char*)"XN: %s",DumpData(Buffer[aktRec].cData,Buffer[aktRec].iTelegramLength));
              } else { // 3.37
                if (cData[3] & 0x01 == 0x01){ 
                  sprintf(line+linePos,"Request Switch %d high Nibble",(int)cData[2]*4);
                } else {
                  sprintf(line+linePos,"Request Switch %d low Nibble",(int)cData[2]*4);
                }
              }
            }
            break;
        case 0x50: // Accessory Decoder operation request
            if (5 != iLength){
                // Invalid 
                sprintf(line+linePos,"Invalid 0x%02X 0x%02X",(int)cData[HEADER],(int)cData[HEADER+1]);
            }
            break;
        case 0x60:
            switch (cData[HEADER+1]){
                case 0x00:
                    sprintf(line+linePos,"All Off");
                    break; 
                case 0x01:
                    sprintf(line+linePos,"All On");
                    break; 
                case 0x02:
                    sprintf(line+linePos,"programming mode");
                    break; 
                case 0x03:
                    sprintf(line+linePos,"modell time");
                    break; 
                case 0x10:
                    sprintf(line+linePos,"P-Info 3 byte");
                    break; 
                case 0x11:
                    sprintf(line+linePos,"P-Info ready");
                    break; 
                case 0x12:
                    sprintf(line+linePos,"P-Info short");
                    break; 
                case 0x13:
                    sprintf(line+linePos,"P-Info no data");
                    break; 
                case 0x14:
                    sprintf(line+linePos,"P-Info CV %d %d",(int)cData[3],(int)cData[4]);
                    break; 
                case 0x15:
                    sprintf(line+linePos,"P-Info CV %d %d",(int)(cData[3]+256),(int)cData[4]);
                    break; 
                case 0x16:
                    sprintf(line+linePos,"P-Info CV %d %d",(int)(cData[3]+512),(int)cData[4]);
                    break; 
                case 0x17:
                    sprintf(line+linePos,"P-Info CV %d %d",(int)(cData[3]+768),(int)cData[4]);
                    break; 
                case 0x1f:
                    sprintf(line+linePos,"P-Info busy");
                    break; 
                case 0x20:
                    sprintf(line+linePos,"Service Variable");
                    break; 
                case 0x21:
                    sprintf(line+linePos,"Software %d %d",(int)cData[3],(int)cData[4]);
                    break; 
                case 0x22:
                    sprintf(line+linePos,"Status Central %d",(int)cData[3]);
                    break; 
                case 0x23:
                    sprintf(line+linePos,"Ext Version Info");
                    break; 
                case 0x24:
                    sprintf(line+linePos,"PoM Result %d %d",LOK_ADRESS(cData[3],cData[4]),(int)cData[5]);
                    break; 
                case 0x25:
                    sprintf(line+linePos,"Model Time");
                    break; 
                case 0x80:
                    sprintf(line+linePos,"Communication Error");
                    syslog.printf(FAC_LOCAL7, PRI_ERROR, (char*)"XN: %s",DumpData(Buffer[aktRec].cData,Buffer[aktRec].iTelegramLength));
                    break; 
                case 0x81:
                    sprintf(line+linePos,"Busy Control Station");
                    break; 
                case 0x82:
                    sprintf(line+linePos,"Unknown command");
                    break; 
                default:
                    sprintf(line+linePos,"Invalid 0x%02X 0x%02X",(int)cData[HEADER],(int)cData[HEADER+1]);
                    break;
            }
            break;
        case 0x70: // BiDi Message
            break;
        case 0x80: // Stop all locomotives request (emergency stop)
            switch (cData[HEADER+1]){
                case 0x00:
                    sprintf(line+linePos,"All Loco Off");
                    break;
                default: 
                    sprintf(line+linePos,"Invalid 0x%02X 0x%02X",(int)cData[HEADER],(int)cData[HEADER+1]);
                    break;
            }
            break;
        case 0x90: // Emergency stop a locomotive
            break;
        case 0xA0: // Locomotive information request
            if ((4 != iLength) && (5 != iLength)){
                // Invalid 
                sprintf(line+linePos,"Invalid 0x%02X 0x%02X",(int)cData[HEADER],(int)cData[HEADER+1]);
            }
            break;
        case 0xB0: // Locomotive operation (old command from X-Bus V1)
            if ((6 != iLength) && (7 != iLength)){
                // Invalid 
                sprintf(line+linePos,"Invalid 0x%02X 0x%02X",(int)cData[HEADER],(int)cData[HEADER+1]);
            }
            break;
        case 0xC0:
            switch (cData[HEADER+1]){
                case 0x04: // Dissolve Double Header
                    break;
                case 0x05: // Establish Double Header
                    break;
                default:    // Invalid
                    sprintf(line+linePos,"Invalid 0x%02X 0x%02X",(int)cData[HEADER],(int)cData[HEADER+1]);
                     break;
            } 
            break;
        case 0xD0: // Invalid
            sprintf(line+linePos,"Invalid 0x%02X 0x%02X",(int)cData[3],(int)cData[4]);
            break;
        case 0xE0:
            if (response && cData[HEADER]== 0xE4){
                sprintf(line+linePos,"Locomotive information Id: 0x%02X Speed %d Fkt: 0x%02x 0x%02x",(int)cData[2],(int)cData[3],(int)cData[4],(int)cData[5]);
                return line;
            }
            if (response && cData[HEADER]== 0xE5){
                sprintf(line+linePos,"Muli Traction member");
                return line;
            }
            if (response && cData[HEADER]== 0xE2){
                sprintf(line+linePos,"MTR Base");
                return line;
            }
            if (response && cData[HEADER]== 0xE6){
                sprintf(line+linePos,"Lok ist DTR");
                return line;
            }

            switch (cData[HEADER+1]){
                case 0x00: // Locomotive information request                    
                    sprintf(line+linePos,"Locomotive information request %d",LOK_ADRESS(cData[3],cData[4]));
                    break;
                case 0x01: // Address inquiry member of a Multi-unit request
                    sprintf(line+linePos,"Address inquiry member of a Multi-unit request up");
                    break; 
                case 0x02:
                    sprintf(line+linePos,"Address inquiry member of a Multi-unit request down");
                    break;
                case 0x03: // Address inquiry Multi-unit request
                    sprintf(line+linePos,"Address inquiry Multi-unit request up");
                    break;
                case 0x04:
                    sprintf(line+linePos,"Address inquiry Multi-unit request down");
                    break;
                case 0x05: // Address inquiry locomotive at command station stack request
                    sprintf(line+linePos,"Address inquiry CS Stack up");
                    break;
                case 0x06:
                    sprintf(line+linePos,"Address inquiry CS Stack down");
                    break;
                case 0x07: // Function status request
                    sprintf(line+linePos,"Function status request %d",LOK_ADRESS(cData[3],cData[4]));
                    break;
                case 0x08: // Function status request F13-F28
                    sprintf(line+linePos,"Function status request F13-F28 %d",LOK_ADRESS(cData[3],cData[4]));
                    break;
                case 0x09: // Function level request F13-F28
                    sprintf(line+linePos,"Function level request %d",LOK_ADRESS(cData[3],cData[4]));
                    break;
                case 0x10: // Locomotive speed and direction operation - 14 speed step
                    sprintf(line+linePos,"Loco %d speed F14 %d ",LOK_ADRESS(cData[3],cData[4]),(int)cData[5]);
                    break;
                case 0x11: // Locomotive speed and direction operation - 27 speed step
                    sprintf(line+linePos,"Loco %d speed F27 %d ",LOK_ADRESS(cData[3],cData[4]),(int)cData[5]);
                    break;
                case 0x12: // Locomotive speed and direction operation - 28 speed step
                    sprintf(line+linePos,"Loco %d speed F28 %d ",LOK_ADRESS(cData[3],cData[4]),(int)cData[5]);
                    break;
                case 0x13: // Locomotive speed and direction operation - 128 speed step
                    sprintf(line+linePos,"Loco %d speed F128 %d ",LOK_ADRESS(cData[3],cData[4]),(int)cData[5]);
                    break;
                case 0x20: // Function operation instruction - Group 1
                    sprintf(line+linePos,"Loco %d Function Group 1 0x%02X",LOK_ADRESS(cData[3],cData[4]),(int)cData[5]);
                    break;
                case 0x21: // Function operation instruction - Group 2
                    sprintf(line+linePos,"Loco %d Function Group 2 0x%02X",LOK_ADRESS(cData[3],cData[4]),(int)cData[5]);
                    break;
                case 0x22: // Function operation instruction - Group 3
                    sprintf(line+linePos,"Loco %d Function Group 3 0x%02X",LOK_ADRESS(cData[3],cData[4]),(int)cData[5]);
                    break;
                case 0x23: // Function operation instruction - Group 4
                    sprintf(line+linePos,"Loco %d Function Group 4 0x%02X",LOK_ADRESS(cData[3],cData[4]),(int)cData[5]);
                    break;
                case 0x24: // Set function state - Group 1
                    sprintf(line+linePos,"Loco %d Function state Group 1 0x%02X",LOK_ADRESS(cData[3],cData[4]),(int)cData[5]);
                    break;
                case 0x25: // Set function state - Group 2
                    sprintf(line+linePos,"Loco %d Function state Group 2 0x%02X",LOK_ADRESS(cData[3],cData[4]),(int)cData[5]);
                    break;
                case 0x26: // Set function state - Group 3
                    sprintf(line+linePos,"Loco %d Function state Group 3 0x%02X",LOK_ADRESS(cData[3],cData[4]),(int)cData[5]);
                    break;
                case 0x27: // Set function state - Group 4
                    sprintf(line+linePos,"Loco %d Function state Group 4 0x%02X",LOK_ADRESS(cData[3],cData[4]),(int)cData[5]);
                    break;
                case 0x28: // Function operation instruction - Group 5
                    sprintf(line+linePos,"Loco %d Function Group 5 0x%02X",LOK_ADRESS(cData[3],cData[4]),(int)cData[5]);
                    break;
                case 0x2C: // Set function state - Group 5
                    sprintf(line+linePos,"Loco %d Function state Group 5 0x%02X",LOK_ADRESS(cData[3],cData[4]),(int)cData[5]);
                    break;
                case 0x2F: // Set function refresh mode
                    sprintf(line+linePos,"Loco %d Function refresh mode 0x%02X",LOK_ADRESS(cData[3],cData[4]),(int)cData[5]);
                    break;
                case 0x30: // Programming on main
                    sprintf(line+linePos,"Programming on main to"); // ToDo
                    break;
                case 0x40:
                    sprintf(line+linePos,"Loco %d busy",LOK_ADRESS(cData[3],cData[4]));
                    break;

                case 0x41:
                case 0x42:
                case 0x43:
                case 0x44:
                    sprintf(line+linePos,"Double Header"); // ToDo
                    break;
                case 0x50:
                    sprintf(line+linePos,"Function state F0-F7 0x%02X F8-F12 0x%02X",(int)cData[3],(int)cData[4]);
                    break;
                case 0x51:
                    sprintf(line+linePos,"Function status F13-F20 0x%02X F21-F28 0x%02X",(int)cData[3],(int)cData[4]);
                    break;
                case 0x54:
                    sprintf(line+linePos,"Function status F29-F36 0x%02X F37-F44 0x%02X F45-F52 0x%02X F56-F63 0x%02X F64-F68 0x%02X",(int)cData[3],(int)cData[4],(int)cData[5],(int)cData[6],(int)cData[7]);
                    break;
                case 0x52:
                    sprintf(line+linePos,"Function state F13-F20 0x%02X F21-F28 0x%02X",(int)cData[3],(int)cData[4]);
                    break;
                case 0x53:
                    sprintf(line+linePos,"Function state F29-F36 0x%02X F37-F44 0x%02X F45-F52 0x%02X F56-F63 0x%02X F64-F68 0x%02X",(int)cData[3],(int)cData[4],(int)cData[5],(int)cData[6],(int)cData[7]);
                    break;

                case 0xF1: // Library Entry
                    switch (iLength){
                      case 8:
                        sprintf(line+linePos,"Loco %d idx: %d size: %d \"\"",LOK_ADRESS(cData[3],cData[4]),(int)cData[5],(int)cData[6]); 
                        break;
                      case 9:
                        sprintf(line+linePos,"Loco %d idx: %d size: %d \"%c\"",LOK_ADRESS(cData[3],cData[4]),(int)cData[5],(int)cData[6],cData[7]); 
                        break;
                      case 10:
                        sprintf(line+linePos,"Loco %d idx: %d size: %d \"%c%c\"",LOK_ADRESS(cData[3],cData[4]),(int)cData[5],(int)cData[6],cData[7],cData[8]); 
                        break;
                      case 11:
                        sprintf(line+linePos,"Loco %d idx: %d size: %d \"%c%c%c\"",LOK_ADRESS(cData[3],cData[4]),(int)cData[5],(int)cData[6],cData[7],cData[8],
                            cData[9]); 
                        break;
                      case 12:
                        sprintf(line+linePos,"Loco %d idx: %d size: %d \"%c%c%c%c\"",LOK_ADRESS(cData[3],cData[4]),(int)cData[5],(int)cData[6],cData[7],cData[8],
                            cData[9],cData[10]); 
                        break;
                      case 13:
                        sprintf(line+linePos,"Loco %d idx: %d size: %d \"%c%c%c%c%c\"",LOK_ADRESS(cData[3],cData[4]),(int)cData[5],(int)cData[6],cData[7],cData[8],
                            cData[9],cData[10],cData[11]); 
                        break;
                      case 14:
                        sprintf(line+linePos,"Loco %d idx: %d size: %d \"%c%c%c%c%c%c\"",LOK_ADRESS(cData[3],cData[4]),(int)cData[5],(int)cData[6],cData[7],cData[8],
                            cData[9],cData[10],cData[11],cData[12]); 
                        break;
                      case 15:
                        sprintf(line+linePos,"Loco %d idx: %d size: %d \"%c%c%c%c%c%c%c\"",LOK_ADRESS(cData[3],cData[4]),(int)cData[5],(int)cData[6],cData[7],cData[8],
                            cData[9],cData[10],cData[11],cData[12],cData[13]); 
                        break;
                      case 16:
                        sprintf(line+linePos,"Loco %d idx: %d size: %d \"%c%c%c%c%c%c%c%c\"",LOK_ADRESS(cData[3],cData[4]),(int)cData[5],(int)cData[6],cData[7],cData[8],
                            cData[9],cData[10],cData[11],cData[12],cData[13],cData[14]); 
                        break;
                      case 17:
                        sprintf(line+linePos,"Loco %d idx: %d size: %d \"%c%c%c%c%c%c%c%c%c\"",LOK_ADRESS(cData[3],cData[4]),(int)cData[5],(int)cData[6],cData[7],cData[8],
                            cData[9],cData[10],cData[11],cData[12],cData[13],cData[14],cData[15]); 
                        break;
                      case 18:
                        sprintf(line+linePos,"Loco %d idx: %d size: %d \"%c%c%c%c%c%c%c%c%c%c\"",LOK_ADRESS(cData[3],cData[4]),(int)cData[5],(int)cData[6],cData[7],cData[8],
                            cData[9],cData[10],cData[11],cData[12],cData[13],cData[14],cData[15],cData[16]); 
                        break;
                      default:
                        sprintf(line+linePos,"Invalid lib entry"); 
                        break;
                    }
 		    break;
                default: // Invalid
                    sprintf(line+linePos,"Invalid 0x%02X 0x%02X at line %d",(int)cData[HEADER],(int)cData[HEADER+1],__LINE__);
                    break;
            }
            break;
        case 0xF0:
            switch (cData[HEADER+1]){
                case 0x00:
                    break;
                default: // Invalid
                    sprintf(line+linePos,"Invalid 0x%02X 0x%02X at line %d",(int)cData[HEADER],(int)cData[HEADER+1],__LINE__);
                    break;
            }
            break;
    }
    return line;
}

void ESP_OTA_Init() {
  // Port defaults to 3232
  // ArduinoOTA.setPort(3232);

  // Hostname defaults to esp3232-[MAC]
  ArduinoOTA.setHostname(APPLICATION);

  // No authentication by default
  ArduinoOTA.setPassword("admin");

  // Password can be set with it's md5 value as well
  // MD5(admin) = 21232f297a57a5a743894a0e4a801fc3
  // ArduinoOTA.setPasswordHash("21232f297a57a5a743894a0e4a801fc3");
  
   ArduinoOTA.onStart([]() {
    String type;
    if (ArduinoOTA.getCommand() == U_FLASH) {
      type = "sketch";
    } else { // U_FS
      type = "filesystem";
    }
    // NOTE: if updating FS this would be the place to unmount FS using FS.end()
    #if defined(DEBUG)
    Debug.println("Start updating " + type);  //OTA Update Start
    #endif
  });
  ArduinoOTA.onEnd([]() {
    #if defined(DEBUG)
    Debug.println("REBOOT!"); //OTA Update Finish
    #endif
  });
  ArduinoOTA.onProgress([](unsigned int progress, unsigned int total) {
    #if defined(DEBUG)
    Debug.printf("Progress: %u%%", (progress / (total / 100))); // //OTA Update Running
    Debug.println();
    #endif
  });
  ArduinoOTA.onError([](ota_error_t error) {
    #if defined(DEBUG)
    Debug.printf("Error[%u]: ", error);
    if (error == OTA_AUTH_ERROR) {
      Debug.println("Auth Failed");
    } else if (error == OTA_BEGIN_ERROR) {
      Debug.println("Begin Failed");
    } else if (error == OTA_CONNECT_ERROR) {
      Debug.println("Connect Failed");
    } else if (error == OTA_RECEIVE_ERROR) {
      Debug.println("Receive Failed");
    } else if (error == OTA_END_ERROR) {
      Debug.println("End Failed");
    }
    #endif
  });
  ArduinoOTA.begin();
}

void setup() {
  // put your setup code here, to run once:
  // read eeprom for ssid and pass:
  Serial.begin(115200);
  Serial.println("ESP Gestartet");

  WiFi.mode(WIFI_STA);

  WiFi.begin("Garten", "01725124622");

  Serial.print("Verbindung wird hergestellt ...");
  while (WiFi.waitForConnectResult() != WL_CONNECTED) {
    Serial.println("Connection Failed! Rebooting...");
    delay(5000);
    ESP.restart();
  }
  Serial.println();

  Serial.print("Verbunden! IP-Adresse: ");
  Serial.println(WiFi.localIP());
  ESP_OTA_Init();

	// LISTEN_MODE 
	pinMode(MAX485_CONTROL, OUTPUT);
	digitalWrite (MAX485_CONTROL, LOW);	//RECEIVE_MODE
	XNetSwSerial.begin(62500, SWSERIAL_8S1, MAX485_DATA, MAX485_DATA, false, 95); //One Wire Half Duplex Serial, parity mode SPACE
	if (!XNetSwSerial) { // If the object did not initialize, then its configuration is invalid
		Serial.println("Invalid SoftwareSerial pin configuration, check config"); 
		while (1) { // Don't continue with invalid configuration
		delay (1000);
		}
	} 
  Serial.println("XPressNet active scan");
	// high speed half duplex, turn off interrupts during tx
	XNetSwSerial.enableIntTx(false);

}

void loop() {
static uint IdleCount = 0;
  // put your main code here, to run repeatedly:
		if (XNetSwSerial.available()) {      // If anything comes in Serial
			uint8_t data = XNetSwSerial.read();
      if (XNetSwSerial.readParity()) {   //detect parity bit set
          byteRec = 0;
          Buffer[aktRec].iTelegramLength = 0;
      }
      Buffer[aktRec].cData[byteRec++] = data;

      if (byteRec > 3) {
        if (((Buffer[aktRec].cData[1] & 0x0F) + 3 ) == byteRec){
          Buffer[aktRec].iTelegramLength = byteRec;
          syslog.printf(FAC_LOCAL7, PRI_ERROR, AnalyzeXNetPacket((char*)Buffer[aktRec].cData));
//          syslog.printf(FAC_LOCAL7, PRI_ERROR, (char*)"XN: %s",DumpData(Buffer[aktRec].cData,Buffer[aktRec].iTelegramLength));
        }
      }  
      IdleCount = 0;
    } else {
      IdleCount ++;
      if (IdleCount > 100000){
        IdleCount = 0;
        /*
        Serial.println("NO XPressNet telegram received");
        syslog.printf(FAC_LOCAL7, PRI_ERROR, (char*)"No data received");
        */
      }
    }
    ArduinoOTA.handle();
}
