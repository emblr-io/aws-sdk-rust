// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PrepareFlowOutput {
    /// <p>The unique identifier of the flow.</p>
    pub id: ::std::string::String,
    /// <p>The status of the flow. When you submit this request, the status will be <code>NotPrepared</code>. If preparation succeeds, the status becomes <code>Prepared</code>. If it fails, the status becomes <code>FAILED</code>.</p>
    pub status: crate::types::FlowStatus,
    _request_id: Option<String>,
}
impl PrepareFlowOutput {
    /// <p>The unique identifier of the flow.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The status of the flow. When you submit this request, the status will be <code>NotPrepared</code>. If preparation succeeds, the status becomes <code>Prepared</code>. If it fails, the status becomes <code>FAILED</code>.</p>
    pub fn status(&self) -> &crate::types::FlowStatus {
        &self.status
    }
}
impl ::aws_types::request_id::RequestId for PrepareFlowOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PrepareFlowOutput {
    /// Creates a new builder-style object to manufacture [`PrepareFlowOutput`](crate::operation::prepare_flow::PrepareFlowOutput).
    pub fn builder() -> crate::operation::prepare_flow::builders::PrepareFlowOutputBuilder {
        crate::operation::prepare_flow::builders::PrepareFlowOutputBuilder::default()
    }
}

/// A builder for [`PrepareFlowOutput`](crate::operation::prepare_flow::PrepareFlowOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PrepareFlowOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::FlowStatus>,
    _request_id: Option<String>,
}
impl PrepareFlowOutputBuilder {
    /// <p>The unique identifier of the flow.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the flow.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier of the flow.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The status of the flow. When you submit this request, the status will be <code>NotPrepared</code>. If preparation succeeds, the status becomes <code>Prepared</code>. If it fails, the status becomes <code>FAILED</code>.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::FlowStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the flow. When you submit this request, the status will be <code>NotPrepared</code>. If preparation succeeds, the status becomes <code>Prepared</code>. If it fails, the status becomes <code>FAILED</code>.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::FlowStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the flow. When you submit this request, the status will be <code>NotPrepared</code>. If preparation succeeds, the status becomes <code>Prepared</code>. If it fails, the status becomes <code>FAILED</code>.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::FlowStatus> {
        &self.status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PrepareFlowOutput`](crate::operation::prepare_flow::PrepareFlowOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::operation::prepare_flow::builders::PrepareFlowOutputBuilder::id)
    /// - [`status`](crate::operation::prepare_flow::builders::PrepareFlowOutputBuilder::status)
    pub fn build(self) -> ::std::result::Result<crate::operation::prepare_flow::PrepareFlowOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::prepare_flow::PrepareFlowOutput {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building PrepareFlowOutput",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building PrepareFlowOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
