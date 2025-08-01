// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateWorkerBlockInput {
    /// <p>The ID of the Worker to block.</p>
    pub worker_id: ::std::option::Option<::std::string::String>,
    /// <p>A message explaining the reason for blocking the Worker. This parameter enables you to keep track of your Workers. The Worker does not see this message.</p>
    pub reason: ::std::option::Option<::std::string::String>,
}
impl CreateWorkerBlockInput {
    /// <p>The ID of the Worker to block.</p>
    pub fn worker_id(&self) -> ::std::option::Option<&str> {
        self.worker_id.as_deref()
    }
    /// <p>A message explaining the reason for blocking the Worker. This parameter enables you to keep track of your Workers. The Worker does not see this message.</p>
    pub fn reason(&self) -> ::std::option::Option<&str> {
        self.reason.as_deref()
    }
}
impl CreateWorkerBlockInput {
    /// Creates a new builder-style object to manufacture [`CreateWorkerBlockInput`](crate::operation::create_worker_block::CreateWorkerBlockInput).
    pub fn builder() -> crate::operation::create_worker_block::builders::CreateWorkerBlockInputBuilder {
        crate::operation::create_worker_block::builders::CreateWorkerBlockInputBuilder::default()
    }
}

/// A builder for [`CreateWorkerBlockInput`](crate::operation::create_worker_block::CreateWorkerBlockInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateWorkerBlockInputBuilder {
    pub(crate) worker_id: ::std::option::Option<::std::string::String>,
    pub(crate) reason: ::std::option::Option<::std::string::String>,
}
impl CreateWorkerBlockInputBuilder {
    /// <p>The ID of the Worker to block.</p>
    /// This field is required.
    pub fn worker_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.worker_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Worker to block.</p>
    pub fn set_worker_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.worker_id = input;
        self
    }
    /// <p>The ID of the Worker to block.</p>
    pub fn get_worker_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.worker_id
    }
    /// <p>A message explaining the reason for blocking the Worker. This parameter enables you to keep track of your Workers. The Worker does not see this message.</p>
    /// This field is required.
    pub fn reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message explaining the reason for blocking the Worker. This parameter enables you to keep track of your Workers. The Worker does not see this message.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reason = input;
        self
    }
    /// <p>A message explaining the reason for blocking the Worker. This parameter enables you to keep track of your Workers. The Worker does not see this message.</p>
    pub fn get_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.reason
    }
    /// Consumes the builder and constructs a [`CreateWorkerBlockInput`](crate::operation::create_worker_block::CreateWorkerBlockInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_worker_block::CreateWorkerBlockInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_worker_block::CreateWorkerBlockInput {
            worker_id: self.worker_id,
            reason: self.reason,
        })
    }
}
