// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a launch template version that was successfully deleted.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteLaunchTemplateVersionsResponseSuccessItem {
    /// <p>The ID of the launch template.</p>
    pub launch_template_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the launch template.</p>
    pub launch_template_name: ::std::option::Option<::std::string::String>,
    /// <p>The version number of the launch template.</p>
    pub version_number: ::std::option::Option<i64>,
}
impl DeleteLaunchTemplateVersionsResponseSuccessItem {
    /// <p>The ID of the launch template.</p>
    pub fn launch_template_id(&self) -> ::std::option::Option<&str> {
        self.launch_template_id.as_deref()
    }
    /// <p>The name of the launch template.</p>
    pub fn launch_template_name(&self) -> ::std::option::Option<&str> {
        self.launch_template_name.as_deref()
    }
    /// <p>The version number of the launch template.</p>
    pub fn version_number(&self) -> ::std::option::Option<i64> {
        self.version_number
    }
}
impl DeleteLaunchTemplateVersionsResponseSuccessItem {
    /// Creates a new builder-style object to manufacture [`DeleteLaunchTemplateVersionsResponseSuccessItem`](crate::types::DeleteLaunchTemplateVersionsResponseSuccessItem).
    pub fn builder() -> crate::types::builders::DeleteLaunchTemplateVersionsResponseSuccessItemBuilder {
        crate::types::builders::DeleteLaunchTemplateVersionsResponseSuccessItemBuilder::default()
    }
}

/// A builder for [`DeleteLaunchTemplateVersionsResponseSuccessItem`](crate::types::DeleteLaunchTemplateVersionsResponseSuccessItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteLaunchTemplateVersionsResponseSuccessItemBuilder {
    pub(crate) launch_template_id: ::std::option::Option<::std::string::String>,
    pub(crate) launch_template_name: ::std::option::Option<::std::string::String>,
    pub(crate) version_number: ::std::option::Option<i64>,
}
impl DeleteLaunchTemplateVersionsResponseSuccessItemBuilder {
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
    /// <p>The version number of the launch template.</p>
    pub fn version_number(mut self, input: i64) -> Self {
        self.version_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version number of the launch template.</p>
    pub fn set_version_number(mut self, input: ::std::option::Option<i64>) -> Self {
        self.version_number = input;
        self
    }
    /// <p>The version number of the launch template.</p>
    pub fn get_version_number(&self) -> &::std::option::Option<i64> {
        &self.version_number
    }
    /// Consumes the builder and constructs a [`DeleteLaunchTemplateVersionsResponseSuccessItem`](crate::types::DeleteLaunchTemplateVersionsResponseSuccessItem).
    pub fn build(self) -> crate::types::DeleteLaunchTemplateVersionsResponseSuccessItem {
        crate::types::DeleteLaunchTemplateVersionsResponseSuccessItem {
            launch_template_id: self.launch_template_id,
            launch_template_name: self.launch_template_name,
            version_number: self.version_number,
        }
    }
}
