// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetImpersonationRoleOutput {
    /// <p>The impersonation role ID.</p>
    pub impersonation_role_id: ::std::option::Option<::std::string::String>,
    /// <p>The impersonation role name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The impersonation role type.</p>
    pub r#type: ::std::option::Option<crate::types::ImpersonationRoleType>,
    /// <p>The impersonation role description.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The list of rules for the given impersonation role.</p>
    pub rules: ::std::option::Option<::std::vec::Vec<crate::types::ImpersonationRule>>,
    /// <p>The date when the impersonation role was created.</p>
    pub date_created: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date when the impersonation role was last modified.</p>
    pub date_modified: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetImpersonationRoleOutput {
    /// <p>The impersonation role ID.</p>
    pub fn impersonation_role_id(&self) -> ::std::option::Option<&str> {
        self.impersonation_role_id.as_deref()
    }
    /// <p>The impersonation role name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The impersonation role type.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::ImpersonationRoleType> {
        self.r#type.as_ref()
    }
    /// <p>The impersonation role description.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The list of rules for the given impersonation role.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.rules.is_none()`.
    pub fn rules(&self) -> &[crate::types::ImpersonationRule] {
        self.rules.as_deref().unwrap_or_default()
    }
    /// <p>The date when the impersonation role was created.</p>
    pub fn date_created(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.date_created.as_ref()
    }
    /// <p>The date when the impersonation role was last modified.</p>
    pub fn date_modified(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.date_modified.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetImpersonationRoleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetImpersonationRoleOutput {
    /// Creates a new builder-style object to manufacture [`GetImpersonationRoleOutput`](crate::operation::get_impersonation_role::GetImpersonationRoleOutput).
    pub fn builder() -> crate::operation::get_impersonation_role::builders::GetImpersonationRoleOutputBuilder {
        crate::operation::get_impersonation_role::builders::GetImpersonationRoleOutputBuilder::default()
    }
}

/// A builder for [`GetImpersonationRoleOutput`](crate::operation::get_impersonation_role::GetImpersonationRoleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetImpersonationRoleOutputBuilder {
    pub(crate) impersonation_role_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::ImpersonationRoleType>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) rules: ::std::option::Option<::std::vec::Vec<crate::types::ImpersonationRule>>,
    pub(crate) date_created: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) date_modified: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetImpersonationRoleOutputBuilder {
    /// <p>The impersonation role ID.</p>
    pub fn impersonation_role_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.impersonation_role_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The impersonation role ID.</p>
    pub fn set_impersonation_role_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.impersonation_role_id = input;
        self
    }
    /// <p>The impersonation role ID.</p>
    pub fn get_impersonation_role_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.impersonation_role_id
    }
    /// <p>The impersonation role name.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The impersonation role name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The impersonation role name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The impersonation role type.</p>
    pub fn r#type(mut self, input: crate::types::ImpersonationRoleType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The impersonation role type.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ImpersonationRoleType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The impersonation role type.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ImpersonationRoleType> {
        &self.r#type
    }
    /// <p>The impersonation role description.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The impersonation role description.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The impersonation role description.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `rules`.
    ///
    /// To override the contents of this collection use [`set_rules`](Self::set_rules).
    ///
    /// <p>The list of rules for the given impersonation role.</p>
    pub fn rules(mut self, input: crate::types::ImpersonationRule) -> Self {
        let mut v = self.rules.unwrap_or_default();
        v.push(input);
        self.rules = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of rules for the given impersonation role.</p>
    pub fn set_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ImpersonationRule>>) -> Self {
        self.rules = input;
        self
    }
    /// <p>The list of rules for the given impersonation role.</p>
    pub fn get_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ImpersonationRule>> {
        &self.rules
    }
    /// <p>The date when the impersonation role was created.</p>
    pub fn date_created(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.date_created = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date when the impersonation role was created.</p>
    pub fn set_date_created(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.date_created = input;
        self
    }
    /// <p>The date when the impersonation role was created.</p>
    pub fn get_date_created(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.date_created
    }
    /// <p>The date when the impersonation role was last modified.</p>
    pub fn date_modified(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.date_modified = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date when the impersonation role was last modified.</p>
    pub fn set_date_modified(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.date_modified = input;
        self
    }
    /// <p>The date when the impersonation role was last modified.</p>
    pub fn get_date_modified(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.date_modified
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetImpersonationRoleOutput`](crate::operation::get_impersonation_role::GetImpersonationRoleOutput).
    pub fn build(self) -> crate::operation::get_impersonation_role::GetImpersonationRoleOutput {
        crate::operation::get_impersonation_role::GetImpersonationRoleOutput {
            impersonation_role_id: self.impersonation_role_id,
            name: self.name,
            r#type: self.r#type,
            description: self.description,
            rules: self.rules,
            date_created: self.date_created,
            date_modified: self.date_modified,
            _request_id: self._request_id,
        }
    }
}
