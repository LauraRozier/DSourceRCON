{
  Copyright 2018 Thimo Braker <thibmorozier@live.nl>

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
}
{
  ListCommands <ShowDetails [0|1]> (Prints out the information for all commands
                                    in the game.)
  ListPermittedCommands <ShowDetails [0|1]> (Prints out the information for all
                                             commands the player is currently
                                             permitted to execute.)
  ShowCommandInfo <CommandName> (Prints out the details of a particular command)
  ListPlayers (List player ids with associated player name and SteamId)
  ShowNextMap (Ask the server what the next map is)
  AdminKick "<NameOrSteamId>" <KickReason> (Kicks a player from the server)
  AdminKickById <PlayerId> <KickReason> (Kicks a player with Id from the server)
  AdminBan "<NameOrSteamId>" "<BanLength>" <BanReason> (Bans a player from the
                                                        server for a length of
                                                        time.  0 = Perm, 1d = 1
                                                        Day, 1M = 1 Month, etc)
  AdminBanById <PlayerId> "<BanLength>" <BanReason> (Bans player with Id from
                                                     the server for length of
                                                     time. 0 = Perm, 1d = 1 Day,
                                                     1M = 1 Month, etc)
  AdminForceTeamChange <NameOrSteamId> (Changes a player's team.)
  AdminForceTeamChangeById <PlayerId> (Changes a player with a certain id's
                                       team.)
  AdminBroadcast <Message> (Send system message to all players on the server)
  ChatToAdmin <Message> (Send system message to all admins on the server)
  AdminRestartMatch (Tell the server to restart the match)
  AdminEndMatch (Tell the server to immediately end the match)
  AdminPauseMatch (Tell the server to put the match on hold)
  AdminUnpauseMatch (Tell the server to take off the hold)
  AdminKillServer <Force [0|1]> (Tells the server to stop execution)
  AdminChangeMap <MapName> (Change the map and travel to it immediately)
  AdminSetNextMap <MapName> (Set the next map to travel to after this match
                             ends)
  AdminSetMaxNumPlayers <NumPlayers> (Set the maximum number of players for this
                                      server)
  AdminSetNumReservedSlots <NumReserved> (Set the number of reserved player
                                          slots)
  AdminSetServerPassword <Password> (Set the password for a server or use "" to
                                     remove it)
  AdminAddCameraman <NameOrId> (Add a player to the camera man list)
  AdminDemoRec <FileName> (Records gameplay, you must run this first)
  AdminDemoStop (Stops recording and saves the demo to disk)
  AdminListDisconnectedPlayers (List recently disconnected player ids with
                                associated player name and SteamId)
  AdminForceNetUpdateOnClientSaturation <Enabled [0|1]> (If true, when a
                                                         connection becomes
                                                         saturated, all
                                                         remaining actors that
                                                         couldn't complete
                                                         replication will have
                                                         ForceNetUpdate called
                                                         on them)
}
unit SquadRconClient;

interface
uses
  Classes, SysUtils, StrUtils,
  DSourceRCON;

type
  TAdminCommandType = (
    ListCommands, ListPermittedCommands, ShowCommandInfo, ListPlayers,
    ShowNextMap, AdminKick, AdminKickById, AdminBan, AdminBanById,
    AdminForceTeamChange, AdminForceTeamChangeById, AdminBroadcast, ChatToAdmin,
    AdminRestartMatch, AdminEndMatch, AdminPauseMatch, AdminUnpauseMatch,
    AdminKillServer, AdminChangeMap, AdminSetNextMap, AdminSetMaxNumPlayers,
    AdminSetNumReservedSlots, AdminSetServerPassword, AdminAddCameraman,
    AdminDemoRec, AdminDemoStop, AdminListDisconnectedPlayers,
    AdminForceNetUpdateOnClientSaturation
  );

const
  ADMIN_COMMAND_FMT: array[TAdminCommandType] of string = (
    'ListCommands %u',
    'ListPermittedCommands %u',
    'ShowCommandInfo %s',
    'ListPlayers',
    'ShowNextMap',
    'AdminKick "%s" %s',
    'AdminKickById %u %s',
    'AdminBan "%s" "%s" %s',
    'AdminBanById %u "%s" %s',
    'AdminForceTeamChange %s',
    'AdminForceTeamChangeById %u',
    'AdminBroadcast %s',
    'ChatToAdmin %s',
    'AdminRestartMatch',
    'AdminEndMatch',
    'AdminPauseMatch',
    'AdminUnpauseMatch',
    'AdminKillServer %u',
    'AdminChangeMap %s',
    'AdminSetNextMap %s',
    'AdminSetMaxNumPlayers %u',
    'AdminSetNumReservedSlots %u',
    'AdminSetServerPassword %s',
    'AdminAddCameraman %s',
    'AdminDemoRec %s',
    'AdminDemoStop',
    'AdminListDisconnectedPlayers',
    'AdminForceNetUpdateOnClientSaturation %u'
  );

type
  TSquadRconClient = class sealed(TObject)
  strict private
    const
      PACKET_MSG_FMT = 'Packet %s:'#13#10'  Size: %d'#13#10'  ID: %d'#13#10 +
                       '  Type: %s'#13#10'  Data: %s';
    var
      fRCON:            TSourceRCON;
      fDisconnectEvent: TNotifyEvent;
      fErrorEvent,
      fSentEvent,
      fReplyEvent:      TMessageNotifyEvent;
    procedure TriggerDisconnectEvent(Sender: TObject);
    procedure TriggerErrorEvent(aMessage: string);
    procedure TriggerSentEvent(aPacket: TRCONPacket);
    procedure TriggerReplyEvent(aPacket: TRCONPacket);
  public
    constructor Create;
    destructor Destroy; override;
    function Connect(aAddress: string; aPort: Word; aPassword: string): Boolean;
    procedure Send(aCommand: string);
    property OnDisconnect: TNotifyEvent        read fDisconnectEvent write fDisconnectEvent;
    property OnError:      TMessageNotifyEvent read fErrorEvent      write fErrorEvent;
    property OnSent:       TMessageNotifyEvent read fSentEvent       write fSentEvent;
    property OnReply:      TMessageNotifyEvent read fReplyEvent      write fReplyEvent;
  end;

implementation

{ TSquadRconClient }
constructor TSquadRconClient.Create;
begin
  fRCON              := TSourceRCON.Create;
  fRCON.OnDisconnect := TriggerDisconnectEvent;
  fRCON.OnError      := TriggerErrorEvent;
  fRCON.OnSent       := TriggerSentEvent;
  fRCON.OnReply      := TriggerReplyEvent;
end;

destructor TSquadRconClient.Destroy;
begin
  if fRCON <> nil then
  begin
    fRCON.Disconnect;
    FreeAndNil(fRCON);
  end;
end;

function TSquadRconClient.Connect(aAddress: string; aPort: Word; aPassword: string): Boolean;
var
  Endpoint: TIPEndPoint;
begin
  Result        := True;
  Endpoint.Host := aAddress;
  Endpoint.Port := aPort;

  if not fRCON.Connect(Endpoint, aPassword) then
  begin
    fRCON.Disconnect;
    FreeAndNil(fRCON);
    Result := False;
  end;
end;

procedure TSquadRconClient.Send(aCommand: string);
begin
  if aCommand <> '' then
    fRCON.ServerCommand(aCommand);
end;

procedure TSquadRconClient.TriggerDisconnectEvent(Sender: TObject);
begin
  FreeAndNil(fRCON);
  Assert(Assigned(fDisconnectEvent), 'Disconnect event SHOULD ALWAYS be assigned.');
  fDisconnectEvent(Sender);
end;

procedure TSquadRconClient.TriggerErrorEvent(aMessage: string);
begin
  if Assigned(fErrorEvent) then
    fErrorEvent(aMessage);
end;

procedure TSquadRconClient.TriggerSentEvent(aPacket: TRCONPacket);
begin
  if Assigned(fSentEvent) then
    fSentEvent(Format(PACKET_MSG_FMT, [
      'sent',
      aPacket.DataSize,
      aPacket.RequestId,
      LazyPacketTypeToString(aPacket.PacketType),
      IfThen(
        aPacket.PacketType = SERVERDATA_AUTH,
        '<PASSWORD>',
        string(aPacket.Data)
      )
    ]));
end;

procedure TSquadRconClient.TriggerReplyEvent(aPacket: TRCONPacket);
begin
  Assert(Assigned(fReplyEvent), 'Reply event SHOULD ALWAYS be assigned.');

  if aPacket.PacketType = SERVERDATA_AUTH_RESPONSE then
  begin
      fReplyEvent(IfThen(
        aPacket.RequestId = -1,
        'Failed to authenticate',
        'Successfully authenticated'
      ));
  end else
  begin
    fReplyEvent(Format(PACKET_MSG_FMT, [
      'received',
      aPacket.DataSize,
      aPacket.RequestId,
      LazyPacketTypeToString(aPacket.PacketType),
      string(aPacket.Data)
    ]));
  end;
end;

end.
