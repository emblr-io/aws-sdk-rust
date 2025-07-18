// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateScanOutput {
    /// <p>The name of the scan.</p>
    pub scan_name: ::std::string::String,
    /// <p>UUID that identifies the individual scan run.</p>
    pub run_id: ::std::string::String,
    /// <p>The identifier for the resource object that contains resources that were scanned.</p>
    pub resource_id: ::std::option::Option<crate::types::ResourceId>,
    /// <p>The current state of the scan. Returns either <code>InProgress</code>, <code>Successful</code>, or <code>Failed</code>.</p>
    pub scan_state: crate::types::ScanState,
    /// <p>The ARN for the scan name.</p>
    pub scan_name_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateScanOutput {
    /// <p>The name of the scan.</p>
    pub fn scan_name(&self) -> &str {
        use std::ops::Deref;
        self.scan_name.deref()
    }
    /// <p>UUID that identifies the individual scan run.</p>
    pub fn run_id(&self) -> &str {
        use std::ops::Deref;
        self.run_id.deref()
    }
    /// <p>The identifier for the resource object that contains resources that were scanned.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&crate::types::ResourceId> {
        self.resource_id.as_ref()
    }
    /// <p>The current state of the scan. Returns either <code>InProgress</code>, <code>Successful</code>, or <code>Failed</code>.</p>
    pub fn scan_state(&self) -> &crate::types::ScanState {
        &self.scan_state
    }
    /// <p>The ARN for the scan name.</p>
    pub fn scan_name_arn(&self) -> ::std::option::Option<&str> {
        self.scan_name_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateScanOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateScanOutput {
    /// Creates a new builder-style object to manufacture [`CreateScanOutput`](crate::operation::create_scan::CreateScanOutput).
    pub fn builder() -> crate::operation::create_scan::builders::CreateScanOutputBuilder {
        crate::operation::create_scan::builders::CreateScanOutputBuilder::default()
    }
}

/// A builder for [`CreateScanOutput`](crate::operation::create_scan::CreateScanOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateScanOutputBuilder {
    pub(crate) scan_name: ::std::option::Option<::std::string::String>,
    pub(crate) run_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_id: ::std::option::Option<crate::types::ResourceId>,
    pub(crate) scan_state: ::std::option::Option<crate::types::ScanState>,
    pub(crate) scan_name_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateScanOutputBuilder {
    /// <p>The name of the scan.</p>
    /// This field is required.
    pub fn scan_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scan_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the scan.</p>
    pub fn set_scan_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scan_name = input;
        self
    }
    /// <p>The name of the scan.</p>
    pub fn get_scan_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.scan_name
    }
    /// <p>UUID that identifies the individual scan run.</p>
    /// This field is required.
    pub fn run_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.run_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>UUID that identifies the individual scan run.</p>
    pub fn set_run_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.run_id = input;
        self
    }
    /// <p>UUID that identifies the individual scan run.</p>
    pub fn get_run_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.run_id
    }
    /// <p>The identifier for the resource object that contains resources that were scanned.</p>
    /// This field is required.
    pub fn resource_id(mut self, input: crate::types::ResourceId) -> Self {
        self.resource_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The identifier for the resource object that contains resources that were scanned.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<crate::types::ResourceId>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The identifier for the resource object that contains resources that were scanned.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<crate::types::ResourceId> {
        &self.resource_id
    }
    /// <p>The current state of the scan. Returns either <code>InProgress</code>, <code>Successful</code>, or <code>Failed</code>.</p>
    /// This field is required.
    pub fn scan_state(mut self, input: crate::types::ScanState) -> Self {
        self.scan_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current state of the scan. Returns either <code>InProgress</code>, <code>Successful</code>, or <code>Failed</code>.</p>
    pub fn set_scan_state(mut self, input: ::std::option::Option<crate::types::ScanState>) -> Self {
        self.scan_state = input;
        self
    }
    /// <p>The current state of the scan. Returns either <code>InProgress</code>, <code>Successful</code>, or <code>Failed</code>.</p>
    pub fn get_scan_state(&self) -> &::std::option::Option<crate::types::ScanState> {
        &self.scan_state
    }
    /// <p>The ARN for the scan name.</p>
    pub fn scan_name_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scan_name_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN for the scan name.</p>
    pub fn set_scan_name_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scan_name_arn = input;
        self
    }
    /// <p>The ARN for the scan name.</p>
    pub fn get_scan_name_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.scan_name_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateScanOutput`](crate::operation::create_scan::CreateScanOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`scan_name`](crate::operation::create_scan::builders::CreateScanOutputBuilder::scan_name)
    /// - [`run_id`](crate::operation::create_scan::builders::CreateScanOutputBuilder::run_id)
    /// - [`scan_state`](crate::operation::create_scan::builders::CreateScanOutputBuilder::scan_state)
    pub fn build(self) -> ::std::result::Result<crate::operation::create_scan::CreateScanOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_scan::CreateScanOutput {
            scan_name: self.scan_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "scan_name",
                    "scan_name was not specified but it is required when building CreateScanOutput",
                )
            })?,
            run_id: self.run_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "run_id",
                    "run_id was not specified but it is required when building CreateScanOutput",
                )
            })?,
            resource_id: self.resource_id,
            scan_state: self.scan_state.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "scan_state",
                    "scan_state was not specified but it is required when building CreateScanOutput",
                )
            })?,
            scan_name_arn: self.scan_name_arn,
            _request_id: self._request_id,
        })
    }
}
