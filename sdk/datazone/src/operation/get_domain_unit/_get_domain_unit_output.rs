// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct GetDomainUnitOutput {
    /// <p>The ID of the domain unit.</p>
    pub id: ::std::string::String,
    /// <p>The ID of the domain in which the domain unit lives.</p>
    pub domain_id: ::std::string::String,
    /// <p>The name of the domain unit.</p>
    pub name: ::std::string::String,
    /// <p>The ID of the parent domain unit.</p>
    pub parent_domain_unit_id: ::std::option::Option<::std::string::String>,
    /// <p>The description of the domain unit.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The owners of the domain unit.</p>
    pub owners: ::std::vec::Vec<crate::types::DomainUnitOwnerProperties>,
    /// <p>The time stamp at which the domain unit was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp at which the domain unit was last updated.</p>
    pub last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The user who created the domain unit.</p>
    pub created_by: ::std::option::Option<::std::string::String>,
    /// <p>The user who last updated the domain unit.</p>
    pub last_updated_by: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetDomainUnitOutput {
    /// <p>The ID of the domain unit.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The ID of the domain in which the domain unit lives.</p>
    pub fn domain_id(&self) -> &str {
        use std::ops::Deref;
        self.domain_id.deref()
    }
    /// <p>The name of the domain unit.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The ID of the parent domain unit.</p>
    pub fn parent_domain_unit_id(&self) -> ::std::option::Option<&str> {
        self.parent_domain_unit_id.as_deref()
    }
    /// <p>The description of the domain unit.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The owners of the domain unit.</p>
    pub fn owners(&self) -> &[crate::types::DomainUnitOwnerProperties] {
        use std::ops::Deref;
        self.owners.deref()
    }
    /// <p>The time stamp at which the domain unit was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The timestamp at which the domain unit was last updated.</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_at.as_ref()
    }
    /// <p>The user who created the domain unit.</p>
    pub fn created_by(&self) -> ::std::option::Option<&str> {
        self.created_by.as_deref()
    }
    /// <p>The user who last updated the domain unit.</p>
    pub fn last_updated_by(&self) -> ::std::option::Option<&str> {
        self.last_updated_by.as_deref()
    }
}
impl ::std::fmt::Debug for GetDomainUnitOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GetDomainUnitOutput");
        formatter.field("id", &self.id);
        formatter.field("domain_id", &self.domain_id);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("parent_domain_unit_id", &self.parent_domain_unit_id);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("owners", &self.owners);
        formatter.field("created_at", &self.created_at);
        formatter.field("last_updated_at", &self.last_updated_at);
        formatter.field("created_by", &self.created_by);
        formatter.field("last_updated_by", &self.last_updated_by);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for GetDomainUnitOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetDomainUnitOutput {
    /// Creates a new builder-style object to manufacture [`GetDomainUnitOutput`](crate::operation::get_domain_unit::GetDomainUnitOutput).
    pub fn builder() -> crate::operation::get_domain_unit::builders::GetDomainUnitOutputBuilder {
        crate::operation::get_domain_unit::builders::GetDomainUnitOutputBuilder::default()
    }
}

/// A builder for [`GetDomainUnitOutput`](crate::operation::get_domain_unit::GetDomainUnitOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct GetDomainUnitOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) domain_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) parent_domain_unit_id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) owners: ::std::option::Option<::std::vec::Vec<crate::types::DomainUnitOwnerProperties>>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) created_by: ::std::option::Option<::std::string::String>,
    pub(crate) last_updated_by: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetDomainUnitOutputBuilder {
    /// <p>The ID of the domain unit.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the domain unit.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the domain unit.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The ID of the domain in which the domain unit lives.</p>
    /// This field is required.
    pub fn domain_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the domain in which the domain unit lives.</p>
    pub fn set_domain_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_id = input;
        self
    }
    /// <p>The ID of the domain in which the domain unit lives.</p>
    pub fn get_domain_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_id
    }
    /// <p>The name of the domain unit.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the domain unit.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the domain unit.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The ID of the parent domain unit.</p>
    pub fn parent_domain_unit_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parent_domain_unit_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the parent domain unit.</p>
    pub fn set_parent_domain_unit_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parent_domain_unit_id = input;
        self
    }
    /// <p>The ID of the parent domain unit.</p>
    pub fn get_parent_domain_unit_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.parent_domain_unit_id
    }
    /// <p>The description of the domain unit.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the domain unit.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the domain unit.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `owners`.
    ///
    /// To override the contents of this collection use [`set_owners`](Self::set_owners).
    ///
    /// <p>The owners of the domain unit.</p>
    pub fn owners(mut self, input: crate::types::DomainUnitOwnerProperties) -> Self {
        let mut v = self.owners.unwrap_or_default();
        v.push(input);
        self.owners = ::std::option::Option::Some(v);
        self
    }
    /// <p>The owners of the domain unit.</p>
    pub fn set_owners(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DomainUnitOwnerProperties>>) -> Self {
        self.owners = input;
        self
    }
    /// <p>The owners of the domain unit.</p>
    pub fn get_owners(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DomainUnitOwnerProperties>> {
        &self.owners
    }
    /// <p>The time stamp at which the domain unit was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time stamp at which the domain unit was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The time stamp at which the domain unit was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The timestamp at which the domain unit was last updated.</p>
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp at which the domain unit was last updated.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The timestamp at which the domain unit was last updated.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    /// <p>The user who created the domain unit.</p>
    pub fn created_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user who created the domain unit.</p>
    pub fn set_created_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_by = input;
        self
    }
    /// <p>The user who created the domain unit.</p>
    pub fn get_created_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_by
    }
    /// <p>The user who last updated the domain unit.</p>
    pub fn last_updated_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_updated_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user who last updated the domain unit.</p>
    pub fn set_last_updated_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_updated_by = input;
        self
    }
    /// <p>The user who last updated the domain unit.</p>
    pub fn get_last_updated_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_updated_by
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetDomainUnitOutput`](crate::operation::get_domain_unit::GetDomainUnitOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::operation::get_domain_unit::builders::GetDomainUnitOutputBuilder::id)
    /// - [`domain_id`](crate::operation::get_domain_unit::builders::GetDomainUnitOutputBuilder::domain_id)
    /// - [`name`](crate::operation::get_domain_unit::builders::GetDomainUnitOutputBuilder::name)
    /// - [`owners`](crate::operation::get_domain_unit::builders::GetDomainUnitOutputBuilder::owners)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_domain_unit::GetDomainUnitOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_domain_unit::GetDomainUnitOutput {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building GetDomainUnitOutput",
                )
            })?,
            domain_id: self.domain_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "domain_id",
                    "domain_id was not specified but it is required when building GetDomainUnitOutput",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building GetDomainUnitOutput",
                )
            })?,
            parent_domain_unit_id: self.parent_domain_unit_id,
            description: self.description,
            owners: self.owners.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "owners",
                    "owners was not specified but it is required when building GetDomainUnitOutput",
                )
            })?,
            created_at: self.created_at,
            last_updated_at: self.last_updated_at,
            created_by: self.created_by,
            last_updated_by: self.last_updated_by,
            _request_id: self._request_id,
        })
    }
}
impl ::std::fmt::Debug for GetDomainUnitOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GetDomainUnitOutputBuilder");
        formatter.field("id", &self.id);
        formatter.field("domain_id", &self.domain_id);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("parent_domain_unit_id", &self.parent_domain_unit_id);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("owners", &self.owners);
        formatter.field("created_at", &self.created_at);
        formatter.field("last_updated_at", &self.last_updated_at);
        formatter.field("created_by", &self.created_by);
        formatter.field("last_updated_by", &self.last_updated_by);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
