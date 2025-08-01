// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A permission to a resource granted by batch operation to the principal.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchPermissionsRequestEntry {
    /// <p>A unique identifier for the batch permissions request entry.</p>
    pub id: ::std::string::String,
    /// <p>The principal to be granted a permission.</p>
    pub principal: ::std::option::Option<crate::types::DataLakePrincipal>,
    /// <p>The resource to which the principal is to be granted a permission.</p>
    pub resource: ::std::option::Option<crate::types::Resource>,
    /// <p>The permissions to be granted.</p>
    pub permissions: ::std::option::Option<::std::vec::Vec<crate::types::Permission>>,
    /// <p>A Lake Formation condition, which applies to permissions and opt-ins that contain an expression.</p>
    pub condition: ::std::option::Option<crate::types::Condition>,
    /// <p>Indicates if the option to pass permissions is granted.</p>
    pub permissions_with_grant_option: ::std::option::Option<::std::vec::Vec<crate::types::Permission>>,
}
impl BatchPermissionsRequestEntry {
    /// <p>A unique identifier for the batch permissions request entry.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The principal to be granted a permission.</p>
    pub fn principal(&self) -> ::std::option::Option<&crate::types::DataLakePrincipal> {
        self.principal.as_ref()
    }
    /// <p>The resource to which the principal is to be granted a permission.</p>
    pub fn resource(&self) -> ::std::option::Option<&crate::types::Resource> {
        self.resource.as_ref()
    }
    /// <p>The permissions to be granted.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.permissions.is_none()`.
    pub fn permissions(&self) -> &[crate::types::Permission] {
        self.permissions.as_deref().unwrap_or_default()
    }
    /// <p>A Lake Formation condition, which applies to permissions and opt-ins that contain an expression.</p>
    pub fn condition(&self) -> ::std::option::Option<&crate::types::Condition> {
        self.condition.as_ref()
    }
    /// <p>Indicates if the option to pass permissions is granted.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.permissions_with_grant_option.is_none()`.
    pub fn permissions_with_grant_option(&self) -> &[crate::types::Permission] {
        self.permissions_with_grant_option.as_deref().unwrap_or_default()
    }
}
impl BatchPermissionsRequestEntry {
    /// Creates a new builder-style object to manufacture [`BatchPermissionsRequestEntry`](crate::types::BatchPermissionsRequestEntry).
    pub fn builder() -> crate::types::builders::BatchPermissionsRequestEntryBuilder {
        crate::types::builders::BatchPermissionsRequestEntryBuilder::default()
    }
}

/// A builder for [`BatchPermissionsRequestEntry`](crate::types::BatchPermissionsRequestEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchPermissionsRequestEntryBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) principal: ::std::option::Option<crate::types::DataLakePrincipal>,
    pub(crate) resource: ::std::option::Option<crate::types::Resource>,
    pub(crate) permissions: ::std::option::Option<::std::vec::Vec<crate::types::Permission>>,
    pub(crate) condition: ::std::option::Option<crate::types::Condition>,
    pub(crate) permissions_with_grant_option: ::std::option::Option<::std::vec::Vec<crate::types::Permission>>,
}
impl BatchPermissionsRequestEntryBuilder {
    /// <p>A unique identifier for the batch permissions request entry.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the batch permissions request entry.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>A unique identifier for the batch permissions request entry.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The principal to be granted a permission.</p>
    pub fn principal(mut self, input: crate::types::DataLakePrincipal) -> Self {
        self.principal = ::std::option::Option::Some(input);
        self
    }
    /// <p>The principal to be granted a permission.</p>
    pub fn set_principal(mut self, input: ::std::option::Option<crate::types::DataLakePrincipal>) -> Self {
        self.principal = input;
        self
    }
    /// <p>The principal to be granted a permission.</p>
    pub fn get_principal(&self) -> &::std::option::Option<crate::types::DataLakePrincipal> {
        &self.principal
    }
    /// <p>The resource to which the principal is to be granted a permission.</p>
    pub fn resource(mut self, input: crate::types::Resource) -> Self {
        self.resource = ::std::option::Option::Some(input);
        self
    }
    /// <p>The resource to which the principal is to be granted a permission.</p>
    pub fn set_resource(mut self, input: ::std::option::Option<crate::types::Resource>) -> Self {
        self.resource = input;
        self
    }
    /// <p>The resource to which the principal is to be granted a permission.</p>
    pub fn get_resource(&self) -> &::std::option::Option<crate::types::Resource> {
        &self.resource
    }
    /// Appends an item to `permissions`.
    ///
    /// To override the contents of this collection use [`set_permissions`](Self::set_permissions).
    ///
    /// <p>The permissions to be granted.</p>
    pub fn permissions(mut self, input: crate::types::Permission) -> Self {
        let mut v = self.permissions.unwrap_or_default();
        v.push(input);
        self.permissions = ::std::option::Option::Some(v);
        self
    }
    /// <p>The permissions to be granted.</p>
    pub fn set_permissions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Permission>>) -> Self {
        self.permissions = input;
        self
    }
    /// <p>The permissions to be granted.</p>
    pub fn get_permissions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Permission>> {
        &self.permissions
    }
    /// <p>A Lake Formation condition, which applies to permissions and opt-ins that contain an expression.</p>
    pub fn condition(mut self, input: crate::types::Condition) -> Self {
        self.condition = ::std::option::Option::Some(input);
        self
    }
    /// <p>A Lake Formation condition, which applies to permissions and opt-ins that contain an expression.</p>
    pub fn set_condition(mut self, input: ::std::option::Option<crate::types::Condition>) -> Self {
        self.condition = input;
        self
    }
    /// <p>A Lake Formation condition, which applies to permissions and opt-ins that contain an expression.</p>
    pub fn get_condition(&self) -> &::std::option::Option<crate::types::Condition> {
        &self.condition
    }
    /// Appends an item to `permissions_with_grant_option`.
    ///
    /// To override the contents of this collection use [`set_permissions_with_grant_option`](Self::set_permissions_with_grant_option).
    ///
    /// <p>Indicates if the option to pass permissions is granted.</p>
    pub fn permissions_with_grant_option(mut self, input: crate::types::Permission) -> Self {
        let mut v = self.permissions_with_grant_option.unwrap_or_default();
        v.push(input);
        self.permissions_with_grant_option = ::std::option::Option::Some(v);
        self
    }
    /// <p>Indicates if the option to pass permissions is granted.</p>
    pub fn set_permissions_with_grant_option(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Permission>>) -> Self {
        self.permissions_with_grant_option = input;
        self
    }
    /// <p>Indicates if the option to pass permissions is granted.</p>
    pub fn get_permissions_with_grant_option(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Permission>> {
        &self.permissions_with_grant_option
    }
    /// Consumes the builder and constructs a [`BatchPermissionsRequestEntry`](crate::types::BatchPermissionsRequestEntry).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::BatchPermissionsRequestEntryBuilder::id)
    pub fn build(self) -> ::std::result::Result<crate::types::BatchPermissionsRequestEntry, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BatchPermissionsRequestEntry {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building BatchPermissionsRequestEntry",
                )
            })?,
            principal: self.principal,
            resource: self.resource,
            permissions: self.permissions,
            condition: self.condition,
            permissions_with_grant_option: self.permissions_with_grant_option,
        })
    }
}
