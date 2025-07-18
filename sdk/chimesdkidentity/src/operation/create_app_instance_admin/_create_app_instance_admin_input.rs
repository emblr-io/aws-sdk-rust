// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAppInstanceAdminInput {
    /// <p>The ARN of the administrator of the current <code>AppInstance</code>.</p>
    pub app_instance_admin_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the <code>AppInstance</code>.</p>
    pub app_instance_arn: ::std::option::Option<::std::string::String>,
}
impl CreateAppInstanceAdminInput {
    /// <p>The ARN of the administrator of the current <code>AppInstance</code>.</p>
    pub fn app_instance_admin_arn(&self) -> ::std::option::Option<&str> {
        self.app_instance_admin_arn.as_deref()
    }
    /// <p>The ARN of the <code>AppInstance</code>.</p>
    pub fn app_instance_arn(&self) -> ::std::option::Option<&str> {
        self.app_instance_arn.as_deref()
    }
}
impl CreateAppInstanceAdminInput {
    /// Creates a new builder-style object to manufacture [`CreateAppInstanceAdminInput`](crate::operation::create_app_instance_admin::CreateAppInstanceAdminInput).
    pub fn builder() -> crate::operation::create_app_instance_admin::builders::CreateAppInstanceAdminInputBuilder {
        crate::operation::create_app_instance_admin::builders::CreateAppInstanceAdminInputBuilder::default()
    }
}

/// A builder for [`CreateAppInstanceAdminInput`](crate::operation::create_app_instance_admin::CreateAppInstanceAdminInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAppInstanceAdminInputBuilder {
    pub(crate) app_instance_admin_arn: ::std::option::Option<::std::string::String>,
    pub(crate) app_instance_arn: ::std::option::Option<::std::string::String>,
}
impl CreateAppInstanceAdminInputBuilder {
    /// <p>The ARN of the administrator of the current <code>AppInstance</code>.</p>
    /// This field is required.
    pub fn app_instance_admin_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_instance_admin_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the administrator of the current <code>AppInstance</code>.</p>
    pub fn set_app_instance_admin_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_instance_admin_arn = input;
        self
    }
    /// <p>The ARN of the administrator of the current <code>AppInstance</code>.</p>
    pub fn get_app_instance_admin_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_instance_admin_arn
    }
    /// <p>The ARN of the <code>AppInstance</code>.</p>
    /// This field is required.
    pub fn app_instance_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_instance_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the <code>AppInstance</code>.</p>
    pub fn set_app_instance_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_instance_arn = input;
        self
    }
    /// <p>The ARN of the <code>AppInstance</code>.</p>
    pub fn get_app_instance_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_instance_arn
    }
    /// Consumes the builder and constructs a [`CreateAppInstanceAdminInput`](crate::operation::create_app_instance_admin::CreateAppInstanceAdminInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_app_instance_admin::CreateAppInstanceAdminInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_app_instance_admin::CreateAppInstanceAdminInput {
            app_instance_admin_arn: self.app_instance_admin_arn,
            app_instance_arn: self.app_instance_arn,
        })
    }
}
