// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteRefreshScheduleInput {
    /// <p>The ID of the dataset.</p>
    pub data_set_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services account ID.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the refresh schedule.</p>
    pub schedule_id: ::std::option::Option<::std::string::String>,
}
impl DeleteRefreshScheduleInput {
    /// <p>The ID of the dataset.</p>
    pub fn data_set_id(&self) -> ::std::option::Option<&str> {
        self.data_set_id.as_deref()
    }
    /// <p>The Amazon Web Services account ID.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The ID of the refresh schedule.</p>
    pub fn schedule_id(&self) -> ::std::option::Option<&str> {
        self.schedule_id.as_deref()
    }
}
impl DeleteRefreshScheduleInput {
    /// Creates a new builder-style object to manufacture [`DeleteRefreshScheduleInput`](crate::operation::delete_refresh_schedule::DeleteRefreshScheduleInput).
    pub fn builder() -> crate::operation::delete_refresh_schedule::builders::DeleteRefreshScheduleInputBuilder {
        crate::operation::delete_refresh_schedule::builders::DeleteRefreshScheduleInputBuilder::default()
    }
}

/// A builder for [`DeleteRefreshScheduleInput`](crate::operation::delete_refresh_schedule::DeleteRefreshScheduleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteRefreshScheduleInputBuilder {
    pub(crate) data_set_id: ::std::option::Option<::std::string::String>,
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) schedule_id: ::std::option::Option<::std::string::String>,
}
impl DeleteRefreshScheduleInputBuilder {
    /// <p>The ID of the dataset.</p>
    /// This field is required.
    pub fn data_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the dataset.</p>
    pub fn set_data_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_set_id = input;
        self
    }
    /// <p>The ID of the dataset.</p>
    pub fn get_data_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_set_id
    }
    /// <p>The Amazon Web Services account ID.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The ID of the refresh schedule.</p>
    /// This field is required.
    pub fn schedule_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schedule_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the refresh schedule.</p>
    pub fn set_schedule_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schedule_id = input;
        self
    }
    /// <p>The ID of the refresh schedule.</p>
    pub fn get_schedule_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.schedule_id
    }
    /// Consumes the builder and constructs a [`DeleteRefreshScheduleInput`](crate::operation::delete_refresh_schedule::DeleteRefreshScheduleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_refresh_schedule::DeleteRefreshScheduleInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_refresh_schedule::DeleteRefreshScheduleInput {
            data_set_id: self.data_set_id,
            aws_account_id: self.aws_account_id,
            schedule_id: self.schedule_id,
        })
    }
}
