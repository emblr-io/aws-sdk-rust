// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the WorkSpace application.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WorkSpaceApplication {
    /// <p>The identifier of the application.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>The time the application is created.</p>
    pub created: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The description of the WorkSpace application.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The license availability for the applications.</p>
    pub license_type: ::std::option::Option<crate::types::WorkSpaceApplicationLicenseType>,
    /// <p>The name of the WorkSpace application.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The owner of the WorkSpace application.</p>
    pub owner: ::std::option::Option<::std::string::String>,
    /// <p>The status of WorkSpace application.</p>
    pub state: ::std::option::Option<crate::types::WorkSpaceApplicationState>,
    /// <p>The supported compute types of the WorkSpace application.</p>
    pub supported_compute_type_names: ::std::option::Option<::std::vec::Vec<crate::types::Compute>>,
    /// <p>The supported operating systems of the WorkSpace application.</p>
    pub supported_operating_system_names: ::std::option::Option<::std::vec::Vec<crate::types::OperatingSystemName>>,
}
impl WorkSpaceApplication {
    /// <p>The identifier of the application.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>The time the application is created.</p>
    pub fn created(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created.as_ref()
    }
    /// <p>The description of the WorkSpace application.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The license availability for the applications.</p>
    pub fn license_type(&self) -> ::std::option::Option<&crate::types::WorkSpaceApplicationLicenseType> {
        self.license_type.as_ref()
    }
    /// <p>The name of the WorkSpace application.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The owner of the WorkSpace application.</p>
    pub fn owner(&self) -> ::std::option::Option<&str> {
        self.owner.as_deref()
    }
    /// <p>The status of WorkSpace application.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::WorkSpaceApplicationState> {
        self.state.as_ref()
    }
    /// <p>The supported compute types of the WorkSpace application.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.supported_compute_type_names.is_none()`.
    pub fn supported_compute_type_names(&self) -> &[crate::types::Compute] {
        self.supported_compute_type_names.as_deref().unwrap_or_default()
    }
    /// <p>The supported operating systems of the WorkSpace application.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.supported_operating_system_names.is_none()`.
    pub fn supported_operating_system_names(&self) -> &[crate::types::OperatingSystemName] {
        self.supported_operating_system_names.as_deref().unwrap_or_default()
    }
}
impl WorkSpaceApplication {
    /// Creates a new builder-style object to manufacture [`WorkSpaceApplication`](crate::types::WorkSpaceApplication).
    pub fn builder() -> crate::types::builders::WorkSpaceApplicationBuilder {
        crate::types::builders::WorkSpaceApplicationBuilder::default()
    }
}

/// A builder for [`WorkSpaceApplication`](crate::types::WorkSpaceApplication).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkSpaceApplicationBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) created: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) license_type: ::std::option::Option<crate::types::WorkSpaceApplicationLicenseType>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) owner: ::std::option::Option<::std::string::String>,
    pub(crate) state: ::std::option::Option<crate::types::WorkSpaceApplicationState>,
    pub(crate) supported_compute_type_names: ::std::option::Option<::std::vec::Vec<crate::types::Compute>>,
    pub(crate) supported_operating_system_names: ::std::option::Option<::std::vec::Vec<crate::types::OperatingSystemName>>,
}
impl WorkSpaceApplicationBuilder {
    /// <p>The identifier of the application.</p>
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the application.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The identifier of the application.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>The time the application is created.</p>
    pub fn created(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the application is created.</p>
    pub fn set_created(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created = input;
        self
    }
    /// <p>The time the application is created.</p>
    pub fn get_created(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created
    }
    /// <p>The description of the WorkSpace application.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the WorkSpace application.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the WorkSpace application.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The license availability for the applications.</p>
    pub fn license_type(mut self, input: crate::types::WorkSpaceApplicationLicenseType) -> Self {
        self.license_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The license availability for the applications.</p>
    pub fn set_license_type(mut self, input: ::std::option::Option<crate::types::WorkSpaceApplicationLicenseType>) -> Self {
        self.license_type = input;
        self
    }
    /// <p>The license availability for the applications.</p>
    pub fn get_license_type(&self) -> &::std::option::Option<crate::types::WorkSpaceApplicationLicenseType> {
        &self.license_type
    }
    /// <p>The name of the WorkSpace application.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the WorkSpace application.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the WorkSpace application.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The owner of the WorkSpace application.</p>
    pub fn owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The owner of the WorkSpace application.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner = input;
        self
    }
    /// <p>The owner of the WorkSpace application.</p>
    pub fn get_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner
    }
    /// <p>The status of WorkSpace application.</p>
    pub fn state(mut self, input: crate::types::WorkSpaceApplicationState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of WorkSpace application.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::WorkSpaceApplicationState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The status of WorkSpace application.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::WorkSpaceApplicationState> {
        &self.state
    }
    /// Appends an item to `supported_compute_type_names`.
    ///
    /// To override the contents of this collection use [`set_supported_compute_type_names`](Self::set_supported_compute_type_names).
    ///
    /// <p>The supported compute types of the WorkSpace application.</p>
    pub fn supported_compute_type_names(mut self, input: crate::types::Compute) -> Self {
        let mut v = self.supported_compute_type_names.unwrap_or_default();
        v.push(input);
        self.supported_compute_type_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The supported compute types of the WorkSpace application.</p>
    pub fn set_supported_compute_type_names(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Compute>>) -> Self {
        self.supported_compute_type_names = input;
        self
    }
    /// <p>The supported compute types of the WorkSpace application.</p>
    pub fn get_supported_compute_type_names(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Compute>> {
        &self.supported_compute_type_names
    }
    /// Appends an item to `supported_operating_system_names`.
    ///
    /// To override the contents of this collection use [`set_supported_operating_system_names`](Self::set_supported_operating_system_names).
    ///
    /// <p>The supported operating systems of the WorkSpace application.</p>
    pub fn supported_operating_system_names(mut self, input: crate::types::OperatingSystemName) -> Self {
        let mut v = self.supported_operating_system_names.unwrap_or_default();
        v.push(input);
        self.supported_operating_system_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The supported operating systems of the WorkSpace application.</p>
    pub fn set_supported_operating_system_names(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::OperatingSystemName>>) -> Self {
        self.supported_operating_system_names = input;
        self
    }
    /// <p>The supported operating systems of the WorkSpace application.</p>
    pub fn get_supported_operating_system_names(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OperatingSystemName>> {
        &self.supported_operating_system_names
    }
    /// Consumes the builder and constructs a [`WorkSpaceApplication`](crate::types::WorkSpaceApplication).
    pub fn build(self) -> crate::types::WorkSpaceApplication {
        crate::types::WorkSpaceApplication {
            application_id: self.application_id,
            created: self.created,
            description: self.description,
            license_type: self.license_type,
            name: self.name,
            owner: self.owner,
            state: self.state,
            supported_compute_type_names: self.supported_compute_type_names,
            supported_operating_system_names: self.supported_operating_system_names,
        }
    }
}
