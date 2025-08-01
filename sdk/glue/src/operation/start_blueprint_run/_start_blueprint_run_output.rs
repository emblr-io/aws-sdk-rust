// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartBlueprintRunOutput {
    /// <p>The run ID for this blueprint run.</p>
    pub run_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartBlueprintRunOutput {
    /// <p>The run ID for this blueprint run.</p>
    pub fn run_id(&self) -> ::std::option::Option<&str> {
        self.run_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for StartBlueprintRunOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartBlueprintRunOutput {
    /// Creates a new builder-style object to manufacture [`StartBlueprintRunOutput`](crate::operation::start_blueprint_run::StartBlueprintRunOutput).
    pub fn builder() -> crate::operation::start_blueprint_run::builders::StartBlueprintRunOutputBuilder {
        crate::operation::start_blueprint_run::builders::StartBlueprintRunOutputBuilder::default()
    }
}

/// A builder for [`StartBlueprintRunOutput`](crate::operation::start_blueprint_run::StartBlueprintRunOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartBlueprintRunOutputBuilder {
    pub(crate) run_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartBlueprintRunOutputBuilder {
    /// <p>The run ID for this blueprint run.</p>
    pub fn run_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.run_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The run ID for this blueprint run.</p>
    pub fn set_run_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.run_id = input;
        self
    }
    /// <p>The run ID for this blueprint run.</p>
    pub fn get_run_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.run_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartBlueprintRunOutput`](crate::operation::start_blueprint_run::StartBlueprintRunOutput).
    pub fn build(self) -> crate::operation::start_blueprint_run::StartBlueprintRunOutput {
        crate::operation::start_blueprint_run::StartBlueprintRunOutput {
            run_id: self.run_id,
            _request_id: self._request_id,
        }
    }
}
