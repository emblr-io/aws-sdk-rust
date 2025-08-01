// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateGameServerInput {
    /// <p>A unique identifier for the game server group where the game server is running.</p>
    pub game_server_group_name: ::std::option::Option<::std::string::String>,
    /// <p>A custom string that uniquely identifies the game server to update.</p>
    pub game_server_id: ::std::option::Option<::std::string::String>,
    /// <p>A set of custom game server properties, formatted as a single string value. This data is passed to a game client or service when it requests information on game servers.</p>
    pub game_server_data: ::std::option::Option<::std::string::String>,
    /// <p>Indicates if the game server is available or is currently hosting gameplay. You can update a game server status from <code>AVAILABLE</code> to <code>UTILIZED</code>, but you can't change a the status from <code>UTILIZED</code> to <code>AVAILABLE</code>.</p>
    pub utilization_status: ::std::option::Option<crate::types::GameServerUtilizationStatus>,
    /// <p>Indicates health status of the game server. A request that includes this parameter updates the game server's <i>LastHealthCheckTime</i> timestamp.</p>
    pub health_check: ::std::option::Option<crate::types::GameServerHealthCheck>,
}
impl UpdateGameServerInput {
    /// <p>A unique identifier for the game server group where the game server is running.</p>
    pub fn game_server_group_name(&self) -> ::std::option::Option<&str> {
        self.game_server_group_name.as_deref()
    }
    /// <p>A custom string that uniquely identifies the game server to update.</p>
    pub fn game_server_id(&self) -> ::std::option::Option<&str> {
        self.game_server_id.as_deref()
    }
    /// <p>A set of custom game server properties, formatted as a single string value. This data is passed to a game client or service when it requests information on game servers.</p>
    pub fn game_server_data(&self) -> ::std::option::Option<&str> {
        self.game_server_data.as_deref()
    }
    /// <p>Indicates if the game server is available or is currently hosting gameplay. You can update a game server status from <code>AVAILABLE</code> to <code>UTILIZED</code>, but you can't change a the status from <code>UTILIZED</code> to <code>AVAILABLE</code>.</p>
    pub fn utilization_status(&self) -> ::std::option::Option<&crate::types::GameServerUtilizationStatus> {
        self.utilization_status.as_ref()
    }
    /// <p>Indicates health status of the game server. A request that includes this parameter updates the game server's <i>LastHealthCheckTime</i> timestamp.</p>
    pub fn health_check(&self) -> ::std::option::Option<&crate::types::GameServerHealthCheck> {
        self.health_check.as_ref()
    }
}
impl UpdateGameServerInput {
    /// Creates a new builder-style object to manufacture [`UpdateGameServerInput`](crate::operation::update_game_server::UpdateGameServerInput).
    pub fn builder() -> crate::operation::update_game_server::builders::UpdateGameServerInputBuilder {
        crate::operation::update_game_server::builders::UpdateGameServerInputBuilder::default()
    }
}

/// A builder for [`UpdateGameServerInput`](crate::operation::update_game_server::UpdateGameServerInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateGameServerInputBuilder {
    pub(crate) game_server_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) game_server_id: ::std::option::Option<::std::string::String>,
    pub(crate) game_server_data: ::std::option::Option<::std::string::String>,
    pub(crate) utilization_status: ::std::option::Option<crate::types::GameServerUtilizationStatus>,
    pub(crate) health_check: ::std::option::Option<crate::types::GameServerHealthCheck>,
}
impl UpdateGameServerInputBuilder {
    /// <p>A unique identifier for the game server group where the game server is running.</p>
    /// This field is required.
    pub fn game_server_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.game_server_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the game server group where the game server is running.</p>
    pub fn set_game_server_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.game_server_group_name = input;
        self
    }
    /// <p>A unique identifier for the game server group where the game server is running.</p>
    pub fn get_game_server_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.game_server_group_name
    }
    /// <p>A custom string that uniquely identifies the game server to update.</p>
    /// This field is required.
    pub fn game_server_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.game_server_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A custom string that uniquely identifies the game server to update.</p>
    pub fn set_game_server_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.game_server_id = input;
        self
    }
    /// <p>A custom string that uniquely identifies the game server to update.</p>
    pub fn get_game_server_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.game_server_id
    }
    /// <p>A set of custom game server properties, formatted as a single string value. This data is passed to a game client or service when it requests information on game servers.</p>
    pub fn game_server_data(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.game_server_data = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A set of custom game server properties, formatted as a single string value. This data is passed to a game client or service when it requests information on game servers.</p>
    pub fn set_game_server_data(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.game_server_data = input;
        self
    }
    /// <p>A set of custom game server properties, formatted as a single string value. This data is passed to a game client or service when it requests information on game servers.</p>
    pub fn get_game_server_data(&self) -> &::std::option::Option<::std::string::String> {
        &self.game_server_data
    }
    /// <p>Indicates if the game server is available or is currently hosting gameplay. You can update a game server status from <code>AVAILABLE</code> to <code>UTILIZED</code>, but you can't change a the status from <code>UTILIZED</code> to <code>AVAILABLE</code>.</p>
    pub fn utilization_status(mut self, input: crate::types::GameServerUtilizationStatus) -> Self {
        self.utilization_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates if the game server is available or is currently hosting gameplay. You can update a game server status from <code>AVAILABLE</code> to <code>UTILIZED</code>, but you can't change a the status from <code>UTILIZED</code> to <code>AVAILABLE</code>.</p>
    pub fn set_utilization_status(mut self, input: ::std::option::Option<crate::types::GameServerUtilizationStatus>) -> Self {
        self.utilization_status = input;
        self
    }
    /// <p>Indicates if the game server is available or is currently hosting gameplay. You can update a game server status from <code>AVAILABLE</code> to <code>UTILIZED</code>, but you can't change a the status from <code>UTILIZED</code> to <code>AVAILABLE</code>.</p>
    pub fn get_utilization_status(&self) -> &::std::option::Option<crate::types::GameServerUtilizationStatus> {
        &self.utilization_status
    }
    /// <p>Indicates health status of the game server. A request that includes this parameter updates the game server's <i>LastHealthCheckTime</i> timestamp.</p>
    pub fn health_check(mut self, input: crate::types::GameServerHealthCheck) -> Self {
        self.health_check = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates health status of the game server. A request that includes this parameter updates the game server's <i>LastHealthCheckTime</i> timestamp.</p>
    pub fn set_health_check(mut self, input: ::std::option::Option<crate::types::GameServerHealthCheck>) -> Self {
        self.health_check = input;
        self
    }
    /// <p>Indicates health status of the game server. A request that includes this parameter updates the game server's <i>LastHealthCheckTime</i> timestamp.</p>
    pub fn get_health_check(&self) -> &::std::option::Option<crate::types::GameServerHealthCheck> {
        &self.health_check
    }
    /// Consumes the builder and constructs a [`UpdateGameServerInput`](crate::operation::update_game_server::UpdateGameServerInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_game_server::UpdateGameServerInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_game_server::UpdateGameServerInput {
            game_server_group_name: self.game_server_group_name,
            game_server_id: self.game_server_id,
            game_server_data: self.game_server_data,
            utilization_status: self.utilization_status,
            health_check: self.health_check,
        })
    }
}
