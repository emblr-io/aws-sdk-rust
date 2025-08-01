// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListEnvironmentAccountConnectionsInput {
    /// <p>The type of account making the <code>ListEnvironmentAccountConnections</code> request.</p>
    pub requested_by: ::std::option::Option<crate::types::EnvironmentAccountConnectionRequesterAccountType>,
    /// <p>The environment name that's associated with each listed environment account connection.</p>
    pub environment_name: ::std::option::Option<::std::string::String>,
    /// <p>The status details for each listed environment account connection.</p>
    pub statuses: ::std::option::Option<::std::vec::Vec<crate::types::EnvironmentAccountConnectionStatus>>,
    /// <p>A token that indicates the location of the next environment account connection in the array of environment account connections, after the list of environment account connections that was previously requested.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of environment account connections to list.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListEnvironmentAccountConnectionsInput {
    /// <p>The type of account making the <code>ListEnvironmentAccountConnections</code> request.</p>
    pub fn requested_by(&self) -> ::std::option::Option<&crate::types::EnvironmentAccountConnectionRequesterAccountType> {
        self.requested_by.as_ref()
    }
    /// <p>The environment name that's associated with each listed environment account connection.</p>
    pub fn environment_name(&self) -> ::std::option::Option<&str> {
        self.environment_name.as_deref()
    }
    /// <p>The status details for each listed environment account connection.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.statuses.is_none()`.
    pub fn statuses(&self) -> &[crate::types::EnvironmentAccountConnectionStatus] {
        self.statuses.as_deref().unwrap_or_default()
    }
    /// <p>A token that indicates the location of the next environment account connection in the array of environment account connections, after the list of environment account connections that was previously requested.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of environment account connections to list.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListEnvironmentAccountConnectionsInput {
    /// Creates a new builder-style object to manufacture [`ListEnvironmentAccountConnectionsInput`](crate::operation::list_environment_account_connections::ListEnvironmentAccountConnectionsInput).
    pub fn builder() -> crate::operation::list_environment_account_connections::builders::ListEnvironmentAccountConnectionsInputBuilder {
        crate::operation::list_environment_account_connections::builders::ListEnvironmentAccountConnectionsInputBuilder::default()
    }
}

/// A builder for [`ListEnvironmentAccountConnectionsInput`](crate::operation::list_environment_account_connections::ListEnvironmentAccountConnectionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListEnvironmentAccountConnectionsInputBuilder {
    pub(crate) requested_by: ::std::option::Option<crate::types::EnvironmentAccountConnectionRequesterAccountType>,
    pub(crate) environment_name: ::std::option::Option<::std::string::String>,
    pub(crate) statuses: ::std::option::Option<::std::vec::Vec<crate::types::EnvironmentAccountConnectionStatus>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListEnvironmentAccountConnectionsInputBuilder {
    /// <p>The type of account making the <code>ListEnvironmentAccountConnections</code> request.</p>
    /// This field is required.
    pub fn requested_by(mut self, input: crate::types::EnvironmentAccountConnectionRequesterAccountType) -> Self {
        self.requested_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of account making the <code>ListEnvironmentAccountConnections</code> request.</p>
    pub fn set_requested_by(mut self, input: ::std::option::Option<crate::types::EnvironmentAccountConnectionRequesterAccountType>) -> Self {
        self.requested_by = input;
        self
    }
    /// <p>The type of account making the <code>ListEnvironmentAccountConnections</code> request.</p>
    pub fn get_requested_by(&self) -> &::std::option::Option<crate::types::EnvironmentAccountConnectionRequesterAccountType> {
        &self.requested_by
    }
    /// <p>The environment name that's associated with each listed environment account connection.</p>
    pub fn environment_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The environment name that's associated with each listed environment account connection.</p>
    pub fn set_environment_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_name = input;
        self
    }
    /// <p>The environment name that's associated with each listed environment account connection.</p>
    pub fn get_environment_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_name
    }
    /// Appends an item to `statuses`.
    ///
    /// To override the contents of this collection use [`set_statuses`](Self::set_statuses).
    ///
    /// <p>The status details for each listed environment account connection.</p>
    pub fn statuses(mut self, input: crate::types::EnvironmentAccountConnectionStatus) -> Self {
        let mut v = self.statuses.unwrap_or_default();
        v.push(input);
        self.statuses = ::std::option::Option::Some(v);
        self
    }
    /// <p>The status details for each listed environment account connection.</p>
    pub fn set_statuses(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EnvironmentAccountConnectionStatus>>) -> Self {
        self.statuses = input;
        self
    }
    /// <p>The status details for each listed environment account connection.</p>
    pub fn get_statuses(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EnvironmentAccountConnectionStatus>> {
        &self.statuses
    }
    /// <p>A token that indicates the location of the next environment account connection in the array of environment account connections, after the list of environment account connections that was previously requested.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that indicates the location of the next environment account connection in the array of environment account connections, after the list of environment account connections that was previously requested.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token that indicates the location of the next environment account connection in the array of environment account connections, after the list of environment account connections that was previously requested.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of environment account connections to list.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of environment account connections to list.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of environment account connections to list.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListEnvironmentAccountConnectionsInput`](crate::operation::list_environment_account_connections::ListEnvironmentAccountConnectionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_environment_account_connections::ListEnvironmentAccountConnectionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_environment_account_connections::ListEnvironmentAccountConnectionsInput {
                requested_by: self.requested_by,
                environment_name: self.environment_name,
                statuses: self.statuses,
                next_token: self.next_token,
                max_results: self.max_results,
            },
        )
    }
}
