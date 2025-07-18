// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetServerStrategiesOutput {
    /// <p>A list of strategy recommendations for the server.</p>
    pub server_strategies: ::std::option::Option<::std::vec::Vec<crate::types::ServerStrategy>>,
    _request_id: Option<String>,
}
impl GetServerStrategiesOutput {
    /// <p>A list of strategy recommendations for the server.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.server_strategies.is_none()`.
    pub fn server_strategies(&self) -> &[crate::types::ServerStrategy] {
        self.server_strategies.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetServerStrategiesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetServerStrategiesOutput {
    /// Creates a new builder-style object to manufacture [`GetServerStrategiesOutput`](crate::operation::get_server_strategies::GetServerStrategiesOutput).
    pub fn builder() -> crate::operation::get_server_strategies::builders::GetServerStrategiesOutputBuilder {
        crate::operation::get_server_strategies::builders::GetServerStrategiesOutputBuilder::default()
    }
}

/// A builder for [`GetServerStrategiesOutput`](crate::operation::get_server_strategies::GetServerStrategiesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetServerStrategiesOutputBuilder {
    pub(crate) server_strategies: ::std::option::Option<::std::vec::Vec<crate::types::ServerStrategy>>,
    _request_id: Option<String>,
}
impl GetServerStrategiesOutputBuilder {
    /// Appends an item to `server_strategies`.
    ///
    /// To override the contents of this collection use [`set_server_strategies`](Self::set_server_strategies).
    ///
    /// <p>A list of strategy recommendations for the server.</p>
    pub fn server_strategies(mut self, input: crate::types::ServerStrategy) -> Self {
        let mut v = self.server_strategies.unwrap_or_default();
        v.push(input);
        self.server_strategies = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of strategy recommendations for the server.</p>
    pub fn set_server_strategies(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ServerStrategy>>) -> Self {
        self.server_strategies = input;
        self
    }
    /// <p>A list of strategy recommendations for the server.</p>
    pub fn get_server_strategies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ServerStrategy>> {
        &self.server_strategies
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetServerStrategiesOutput`](crate::operation::get_server_strategies::GetServerStrategiesOutput).
    pub fn build(self) -> crate::operation::get_server_strategies::GetServerStrategiesOutput {
        crate::operation::get_server_strategies::GetServerStrategiesOutput {
            server_strategies: self.server_strategies,
            _request_id: self._request_id,
        }
    }
}
