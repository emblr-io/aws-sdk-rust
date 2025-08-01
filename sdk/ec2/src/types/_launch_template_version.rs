// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a launch template version.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LaunchTemplateVersion {
    /// <p>The ID of the launch template.</p>
    pub launch_template_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the launch template.</p>
    pub launch_template_name: ::std::option::Option<::std::string::String>,
    /// <p>The version number.</p>
    pub version_number: ::std::option::Option<i64>,
    /// <p>The description for the version.</p>
    pub version_description: ::std::option::Option<::std::string::String>,
    /// <p>The time the version was created.</p>
    pub create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The principal that created the version.</p>
    pub created_by: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether the version is the default version.</p>
    pub default_version: ::std::option::Option<bool>,
    /// <p>Information about the launch template.</p>
    pub launch_template_data: ::std::option::Option<crate::types::ResponseLaunchTemplateData>,
    /// <p>The entity that manages the launch template.</p>
    pub operator: ::std::option::Option<crate::types::OperatorResponse>,
}
impl LaunchTemplateVersion {
    /// <p>The ID of the launch template.</p>
    pub fn launch_template_id(&self) -> ::std::option::Option<&str> {
        self.launch_template_id.as_deref()
    }
    /// <p>The name of the launch template.</p>
    pub fn launch_template_name(&self) -> ::std::option::Option<&str> {
        self.launch_template_name.as_deref()
    }
    /// <p>The version number.</p>
    pub fn version_number(&self) -> ::std::option::Option<i64> {
        self.version_number
    }
    /// <p>The description for the version.</p>
    pub fn version_description(&self) -> ::std::option::Option<&str> {
        self.version_description.as_deref()
    }
    /// <p>The time the version was created.</p>
    pub fn create_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.create_time.as_ref()
    }
    /// <p>The principal that created the version.</p>
    pub fn created_by(&self) -> ::std::option::Option<&str> {
        self.created_by.as_deref()
    }
    /// <p>Indicates whether the version is the default version.</p>
    pub fn default_version(&self) -> ::std::option::Option<bool> {
        self.default_version
    }
    /// <p>Information about the launch template.</p>
    pub fn launch_template_data(&self) -> ::std::option::Option<&crate::types::ResponseLaunchTemplateData> {
        self.launch_template_data.as_ref()
    }
    /// <p>The entity that manages the launch template.</p>
    pub fn operator(&self) -> ::std::option::Option<&crate::types::OperatorResponse> {
        self.operator.as_ref()
    }
}
impl LaunchTemplateVersion {
    /// Creates a new builder-style object to manufacture [`LaunchTemplateVersion`](crate::types::LaunchTemplateVersion).
    pub fn builder() -> crate::types::builders::LaunchTemplateVersionBuilder {
        crate::types::builders::LaunchTemplateVersionBuilder::default()
    }
}

/// A builder for [`LaunchTemplateVersion`](crate::types::LaunchTemplateVersion).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LaunchTemplateVersionBuilder {
    pub(crate) launch_template_id: ::std::option::Option<::std::string::String>,
    pub(crate) launch_template_name: ::std::option::Option<::std::string::String>,
    pub(crate) version_number: ::std::option::Option<i64>,
    pub(crate) version_description: ::std::option::Option<::std::string::String>,
    pub(crate) create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) created_by: ::std::option::Option<::std::string::String>,
    pub(crate) default_version: ::std::option::Option<bool>,
    pub(crate) launch_template_data: ::std::option::Option<crate::types::ResponseLaunchTemplateData>,
    pub(crate) operator: ::std::option::Option<crate::types::OperatorResponse>,
}
impl LaunchTemplateVersionBuilder {
    /// <p>The ID of the launch template.</p>
    pub fn launch_template_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.launch_template_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the launch template.</p>
    pub fn set_launch_template_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.launch_template_id = input;
        self
    }
    /// <p>The ID of the launch template.</p>
    pub fn get_launch_template_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.launch_template_id
    }
    /// <p>The name of the launch template.</p>
    pub fn launch_template_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.launch_template_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the launch template.</p>
    pub fn set_launch_template_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.launch_template_name = input;
        self
    }
    /// <p>The name of the launch template.</p>
    pub fn get_launch_template_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.launch_template_name
    }
    /// <p>The version number.</p>
    pub fn version_number(mut self, input: i64) -> Self {
        self.version_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version number.</p>
    pub fn set_version_number(mut self, input: ::std::option::Option<i64>) -> Self {
        self.version_number = input;
        self
    }
    /// <p>The version number.</p>
    pub fn get_version_number(&self) -> &::std::option::Option<i64> {
        &self.version_number
    }
    /// <p>The description for the version.</p>
    pub fn version_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description for the version.</p>
    pub fn set_version_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_description = input;
        self
    }
    /// <p>The description for the version.</p>
    pub fn get_version_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_description
    }
    /// <p>The time the version was created.</p>
    pub fn create_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the version was created.</p>
    pub fn set_create_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_time = input;
        self
    }
    /// <p>The time the version was created.</p>
    pub fn get_create_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_time
    }
    /// <p>The principal that created the version.</p>
    pub fn created_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The principal that created the version.</p>
    pub fn set_created_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_by = input;
        self
    }
    /// <p>The principal that created the version.</p>
    pub fn get_created_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_by
    }
    /// <p>Indicates whether the version is the default version.</p>
    pub fn default_version(mut self, input: bool) -> Self {
        self.default_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the version is the default version.</p>
    pub fn set_default_version(mut self, input: ::std::option::Option<bool>) -> Self {
        self.default_version = input;
        self
    }
    /// <p>Indicates whether the version is the default version.</p>
    pub fn get_default_version(&self) -> &::std::option::Option<bool> {
        &self.default_version
    }
    /// <p>Information about the launch template.</p>
    pub fn launch_template_data(mut self, input: crate::types::ResponseLaunchTemplateData) -> Self {
        self.launch_template_data = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the launch template.</p>
    pub fn set_launch_template_data(mut self, input: ::std::option::Option<crate::types::ResponseLaunchTemplateData>) -> Self {
        self.launch_template_data = input;
        self
    }
    /// <p>Information about the launch template.</p>
    pub fn get_launch_template_data(&self) -> &::std::option::Option<crate::types::ResponseLaunchTemplateData> {
        &self.launch_template_data
    }
    /// <p>The entity that manages the launch template.</p>
    pub fn operator(mut self, input: crate::types::OperatorResponse) -> Self {
        self.operator = ::std::option::Option::Some(input);
        self
    }
    /// <p>The entity that manages the launch template.</p>
    pub fn set_operator(mut self, input: ::std::option::Option<crate::types::OperatorResponse>) -> Self {
        self.operator = input;
        self
    }
    /// <p>The entity that manages the launch template.</p>
    pub fn get_operator(&self) -> &::std::option::Option<crate::types::OperatorResponse> {
        &self.operator
    }
    /// Consumes the builder and constructs a [`LaunchTemplateVersion`](crate::types::LaunchTemplateVersion).
    pub fn build(self) -> crate::types::LaunchTemplateVersion {
        crate::types::LaunchTemplateVersion {
            launch_template_id: self.launch_template_id,
            launch_template_name: self.launch_template_name,
            version_number: self.version_number,
            version_description: self.version_description,
            create_time: self.create_time,
            created_by: self.created_by,
            default_version: self.default_version,
            launch_template_data: self.launch_template_data,
            operator: self.operator,
        }
    }
}
