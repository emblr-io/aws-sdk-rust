// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateRestoreTestingPlanOutput {
    /// <p>The date and time a restore testing plan was created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationTime</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087AM.</p>
    pub creation_time: ::aws_smithy_types::DateTime,
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies the created restore testing plan.</p>
    pub restore_testing_plan_arn: ::std::string::String,
    /// <p>This unique string is the name of the restore testing plan.</p>
    /// <p>The name cannot be changed after creation. The name consists of only alphanumeric characters and underscores. Maximum length is 50.</p>
    pub restore_testing_plan_name: ::std::string::String,
    _request_id: Option<String>,
}
impl CreateRestoreTestingPlanOutput {
    /// <p>The date and time a restore testing plan was created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationTime</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087AM.</p>
    pub fn creation_time(&self) -> &::aws_smithy_types::DateTime {
        &self.creation_time
    }
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies the created restore testing plan.</p>
    pub fn restore_testing_plan_arn(&self) -> &str {
        use std::ops::Deref;
        self.restore_testing_plan_arn.deref()
    }
    /// <p>This unique string is the name of the restore testing plan.</p>
    /// <p>The name cannot be changed after creation. The name consists of only alphanumeric characters and underscores. Maximum length is 50.</p>
    pub fn restore_testing_plan_name(&self) -> &str {
        use std::ops::Deref;
        self.restore_testing_plan_name.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateRestoreTestingPlanOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateRestoreTestingPlanOutput {
    /// Creates a new builder-style object to manufacture [`CreateRestoreTestingPlanOutput`](crate::operation::create_restore_testing_plan::CreateRestoreTestingPlanOutput).
    pub fn builder() -> crate::operation::create_restore_testing_plan::builders::CreateRestoreTestingPlanOutputBuilder {
        crate::operation::create_restore_testing_plan::builders::CreateRestoreTestingPlanOutputBuilder::default()
    }
}

/// A builder for [`CreateRestoreTestingPlanOutput`](crate::operation::create_restore_testing_plan::CreateRestoreTestingPlanOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateRestoreTestingPlanOutputBuilder {
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) restore_testing_plan_arn: ::std::option::Option<::std::string::String>,
    pub(crate) restore_testing_plan_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateRestoreTestingPlanOutputBuilder {
    /// <p>The date and time a restore testing plan was created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationTime</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087AM.</p>
    /// This field is required.
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time a restore testing plan was created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationTime</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087AM.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The date and time a restore testing plan was created, in Unix format and Coordinated Universal Time (UTC). The value of <code>CreationTime</code> is accurate to milliseconds. For example, the value 1516925490.087 represents Friday, January 26, 2018 12:11:30.087AM.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies the created restore testing plan.</p>
    /// This field is required.
    pub fn restore_testing_plan_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.restore_testing_plan_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies the created restore testing plan.</p>
    pub fn set_restore_testing_plan_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.restore_testing_plan_arn = input;
        self
    }
    /// <p>An Amazon Resource Name (ARN) that uniquely identifies the created restore testing plan.</p>
    pub fn get_restore_testing_plan_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.restore_testing_plan_arn
    }
    /// <p>This unique string is the name of the restore testing plan.</p>
    /// <p>The name cannot be changed after creation. The name consists of only alphanumeric characters and underscores. Maximum length is 50.</p>
    /// This field is required.
    pub fn restore_testing_plan_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.restore_testing_plan_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This unique string is the name of the restore testing plan.</p>
    /// <p>The name cannot be changed after creation. The name consists of only alphanumeric characters and underscores. Maximum length is 50.</p>
    pub fn set_restore_testing_plan_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.restore_testing_plan_name = input;
        self
    }
    /// <p>This unique string is the name of the restore testing plan.</p>
    /// <p>The name cannot be changed after creation. The name consists of only alphanumeric characters and underscores. Maximum length is 50.</p>
    pub fn get_restore_testing_plan_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.restore_testing_plan_name
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateRestoreTestingPlanOutput`](crate::operation::create_restore_testing_plan::CreateRestoreTestingPlanOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`creation_time`](crate::operation::create_restore_testing_plan::builders::CreateRestoreTestingPlanOutputBuilder::creation_time)
    /// - [`restore_testing_plan_arn`](crate::operation::create_restore_testing_plan::builders::CreateRestoreTestingPlanOutputBuilder::restore_testing_plan_arn)
    /// - [`restore_testing_plan_name`](crate::operation::create_restore_testing_plan::builders::CreateRestoreTestingPlanOutputBuilder::restore_testing_plan_name)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_restore_testing_plan::CreateRestoreTestingPlanOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_restore_testing_plan::CreateRestoreTestingPlanOutput {
            creation_time: self.creation_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "creation_time",
                    "creation_time was not specified but it is required when building CreateRestoreTestingPlanOutput",
                )
            })?,
            restore_testing_plan_arn: self.restore_testing_plan_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "restore_testing_plan_arn",
                    "restore_testing_plan_arn was not specified but it is required when building CreateRestoreTestingPlanOutput",
                )
            })?,
            restore_testing_plan_name: self.restore_testing_plan_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "restore_testing_plan_name",
                    "restore_testing_plan_name was not specified but it is required when building CreateRestoreTestingPlanOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
