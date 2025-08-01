// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summary information for an Amazon Q Business application.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Application {
    /// <p>The name of the Amazon Q Business application.</p>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for the Amazon Q Business application.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>The Unix timestamp when the Amazon Q Business application was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Unix timestamp when the Amazon Q Business application was last updated.</p>
    pub updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The status of the Amazon Q Business application. The application is ready to use when the status is <code>ACTIVE</code>.</p>
    pub status: ::std::option::Option<crate::types::ApplicationStatus>,
    /// <p>The authentication type being used by a Amazon Q Business application.</p>
    pub identity_type: ::std::option::Option<crate::types::IdentityType>,
    /// <p>The Amazon QuickSight configuration for an Amazon Q Business application that uses QuickSight as the identity provider.</p>
    pub quick_sight_configuration: ::std::option::Option<crate::types::QuickSightConfiguration>,
}
impl Application {
    /// <p>The name of the Amazon Q Business application.</p>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>The identifier for the Amazon Q Business application.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>The Unix timestamp when the Amazon Q Business application was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The Unix timestamp when the Amazon Q Business application was last updated.</p>
    pub fn updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_at.as_ref()
    }
    /// <p>The status of the Amazon Q Business application. The application is ready to use when the status is <code>ACTIVE</code>.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ApplicationStatus> {
        self.status.as_ref()
    }
    /// <p>The authentication type being used by a Amazon Q Business application.</p>
    pub fn identity_type(&self) -> ::std::option::Option<&crate::types::IdentityType> {
        self.identity_type.as_ref()
    }
    /// <p>The Amazon QuickSight configuration for an Amazon Q Business application that uses QuickSight as the identity provider.</p>
    pub fn quick_sight_configuration(&self) -> ::std::option::Option<&crate::types::QuickSightConfiguration> {
        self.quick_sight_configuration.as_ref()
    }
}
impl Application {
    /// Creates a new builder-style object to manufacture [`Application`](crate::types::Application).
    pub fn builder() -> crate::types::builders::ApplicationBuilder {
        crate::types::builders::ApplicationBuilder::default()
    }
}

/// A builder for [`Application`](crate::types::Application).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ApplicationBuilder {
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status: ::std::option::Option<crate::types::ApplicationStatus>,
    pub(crate) identity_type: ::std::option::Option<crate::types::IdentityType>,
    pub(crate) quick_sight_configuration: ::std::option::Option<crate::types::QuickSightConfiguration>,
}
impl ApplicationBuilder {
    /// <p>The name of the Amazon Q Business application.</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Amazon Q Business application.</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The name of the Amazon Q Business application.</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>The identifier for the Amazon Q Business application.</p>
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the Amazon Q Business application.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The identifier for the Amazon Q Business application.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>The Unix timestamp when the Amazon Q Business application was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Unix timestamp when the Amazon Q Business application was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The Unix timestamp when the Amazon Q Business application was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The Unix timestamp when the Amazon Q Business application was last updated.</p>
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Unix timestamp when the Amazon Q Business application was last updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The Unix timestamp when the Amazon Q Business application was last updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// <p>The status of the Amazon Q Business application. The application is ready to use when the status is <code>ACTIVE</code>.</p>
    pub fn status(mut self, input: crate::types::ApplicationStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the Amazon Q Business application. The application is ready to use when the status is <code>ACTIVE</code>.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ApplicationStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the Amazon Q Business application. The application is ready to use when the status is <code>ACTIVE</code>.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ApplicationStatus> {
        &self.status
    }
    /// <p>The authentication type being used by a Amazon Q Business application.</p>
    pub fn identity_type(mut self, input: crate::types::IdentityType) -> Self {
        self.identity_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The authentication type being used by a Amazon Q Business application.</p>
    pub fn set_identity_type(mut self, input: ::std::option::Option<crate::types::IdentityType>) -> Self {
        self.identity_type = input;
        self
    }
    /// <p>The authentication type being used by a Amazon Q Business application.</p>
    pub fn get_identity_type(&self) -> &::std::option::Option<crate::types::IdentityType> {
        &self.identity_type
    }
    /// <p>The Amazon QuickSight configuration for an Amazon Q Business application that uses QuickSight as the identity provider.</p>
    pub fn quick_sight_configuration(mut self, input: crate::types::QuickSightConfiguration) -> Self {
        self.quick_sight_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon QuickSight configuration for an Amazon Q Business application that uses QuickSight as the identity provider.</p>
    pub fn set_quick_sight_configuration(mut self, input: ::std::option::Option<crate::types::QuickSightConfiguration>) -> Self {
        self.quick_sight_configuration = input;
        self
    }
    /// <p>The Amazon QuickSight configuration for an Amazon Q Business application that uses QuickSight as the identity provider.</p>
    pub fn get_quick_sight_configuration(&self) -> &::std::option::Option<crate::types::QuickSightConfiguration> {
        &self.quick_sight_configuration
    }
    /// Consumes the builder and constructs a [`Application`](crate::types::Application).
    pub fn build(self) -> crate::types::Application {
        crate::types::Application {
            display_name: self.display_name,
            application_id: self.application_id,
            created_at: self.created_at,
            updated_at: self.updated_at,
            status: self.status,
            identity_type: self.identity_type,
            quick_sight_configuration: self.quick_sight_configuration,
        }
    }
}
