// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`ClaimGameServer`](crate::operation::claim_game_server::builders::ClaimGameServerFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`game_server_group_name(impl Into<String>)`](crate::operation::claim_game_server::builders::ClaimGameServerFluentBuilder::game_server_group_name) / [`set_game_server_group_name(Option<String>)`](crate::operation::claim_game_server::builders::ClaimGameServerFluentBuilder::set_game_server_group_name):<br>required: **true**<br><p>A unique identifier for the game server group where the game server is running. If you are not specifying a game server to claim, this value identifies where you want Amazon GameLift Servers FleetIQ to look for an available game server to claim.</p><br>
    ///   - [`game_server_id(impl Into<String>)`](crate::operation::claim_game_server::builders::ClaimGameServerFluentBuilder::game_server_id) / [`set_game_server_id(Option<String>)`](crate::operation::claim_game_server::builders::ClaimGameServerFluentBuilder::set_game_server_id):<br>required: **false**<br><p>A custom string that uniquely identifies the game server to claim. If this parameter is left empty, Amazon GameLift Servers FleetIQ searches for an available game server in the specified game server group.</p><br>
    ///   - [`game_server_data(impl Into<String>)`](crate::operation::claim_game_server::builders::ClaimGameServerFluentBuilder::game_server_data) / [`set_game_server_data(Option<String>)`](crate::operation::claim_game_server::builders::ClaimGameServerFluentBuilder::set_game_server_data):<br>required: **false**<br><p>A set of custom game server properties, formatted as a single string value. This data is passed to a game client or service when it requests information on game servers.</p><br>
    ///   - [`filter_option(ClaimFilterOption)`](crate::operation::claim_game_server::builders::ClaimGameServerFluentBuilder::filter_option) / [`set_filter_option(Option<ClaimFilterOption>)`](crate::operation::claim_game_server::builders::ClaimGameServerFluentBuilder::set_filter_option):<br>required: **false**<br><p>Object that restricts how a claimed game server is chosen.</p><br>
    /// - On success, responds with [`ClaimGameServerOutput`](crate::operation::claim_game_server::ClaimGameServerOutput) with field(s):
    ///   - [`game_server(Option<GameServer>)`](crate::operation::claim_game_server::ClaimGameServerOutput::game_server): <p>Object that describes the newly claimed game server.</p>
    /// - On failure, responds with [`SdkError<ClaimGameServerError>`](crate::operation::claim_game_server::ClaimGameServerError)
    pub fn claim_game_server(&self) -> crate::operation::claim_game_server::builders::ClaimGameServerFluentBuilder {
        crate::operation::claim_game_server::builders::ClaimGameServerFluentBuilder::new(self.handle.clone())
    }
}
