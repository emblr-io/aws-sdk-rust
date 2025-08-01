// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdatePreferencesInput {
    /// <p>The updated preferred rate types for the management account.</p>
    pub management_account_rate_type_selections: ::std::option::Option<::std::vec::Vec<crate::types::RateType>>,
    /// <p>The updated preferred rate types for member accounts.</p>
    pub member_account_rate_type_selections: ::std::option::Option<::std::vec::Vec<crate::types::RateType>>,
    /// <p>The updated preferred rate types for a standalone account.</p>
    pub standalone_account_rate_type_selections: ::std::option::Option<::std::vec::Vec<crate::types::RateType>>,
}
impl UpdatePreferencesInput {
    /// <p>The updated preferred rate types for the management account.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.management_account_rate_type_selections.is_none()`.
    pub fn management_account_rate_type_selections(&self) -> &[crate::types::RateType] {
        self.management_account_rate_type_selections.as_deref().unwrap_or_default()
    }
    /// <p>The updated preferred rate types for member accounts.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.member_account_rate_type_selections.is_none()`.
    pub fn member_account_rate_type_selections(&self) -> &[crate::types::RateType] {
        self.member_account_rate_type_selections.as_deref().unwrap_or_default()
    }
    /// <p>The updated preferred rate types for a standalone account.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.standalone_account_rate_type_selections.is_none()`.
    pub fn standalone_account_rate_type_selections(&self) -> &[crate::types::RateType] {
        self.standalone_account_rate_type_selections.as_deref().unwrap_or_default()
    }
}
impl UpdatePreferencesInput {
    /// Creates a new builder-style object to manufacture [`UpdatePreferencesInput`](crate::operation::update_preferences::UpdatePreferencesInput).
    pub fn builder() -> crate::operation::update_preferences::builders::UpdatePreferencesInputBuilder {
        crate::operation::update_preferences::builders::UpdatePreferencesInputBuilder::default()
    }
}

/// A builder for [`UpdatePreferencesInput`](crate::operation::update_preferences::UpdatePreferencesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdatePreferencesInputBuilder {
    pub(crate) management_account_rate_type_selections: ::std::option::Option<::std::vec::Vec<crate::types::RateType>>,
    pub(crate) member_account_rate_type_selections: ::std::option::Option<::std::vec::Vec<crate::types::RateType>>,
    pub(crate) standalone_account_rate_type_selections: ::std::option::Option<::std::vec::Vec<crate::types::RateType>>,
}
impl UpdatePreferencesInputBuilder {
    /// Appends an item to `management_account_rate_type_selections`.
    ///
    /// To override the contents of this collection use [`set_management_account_rate_type_selections`](Self::set_management_account_rate_type_selections).
    ///
    /// <p>The updated preferred rate types for the management account.</p>
    pub fn management_account_rate_type_selections(mut self, input: crate::types::RateType) -> Self {
        let mut v = self.management_account_rate_type_selections.unwrap_or_default();
        v.push(input);
        self.management_account_rate_type_selections = ::std::option::Option::Some(v);
        self
    }
    /// <p>The updated preferred rate types for the management account.</p>
    pub fn set_management_account_rate_type_selections(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RateType>>) -> Self {
        self.management_account_rate_type_selections = input;
        self
    }
    /// <p>The updated preferred rate types for the management account.</p>
    pub fn get_management_account_rate_type_selections(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RateType>> {
        &self.management_account_rate_type_selections
    }
    /// Appends an item to `member_account_rate_type_selections`.
    ///
    /// To override the contents of this collection use [`set_member_account_rate_type_selections`](Self::set_member_account_rate_type_selections).
    ///
    /// <p>The updated preferred rate types for member accounts.</p>
    pub fn member_account_rate_type_selections(mut self, input: crate::types::RateType) -> Self {
        let mut v = self.member_account_rate_type_selections.unwrap_or_default();
        v.push(input);
        self.member_account_rate_type_selections = ::std::option::Option::Some(v);
        self
    }
    /// <p>The updated preferred rate types for member accounts.</p>
    pub fn set_member_account_rate_type_selections(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RateType>>) -> Self {
        self.member_account_rate_type_selections = input;
        self
    }
    /// <p>The updated preferred rate types for member accounts.</p>
    pub fn get_member_account_rate_type_selections(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RateType>> {
        &self.member_account_rate_type_selections
    }
    /// Appends an item to `standalone_account_rate_type_selections`.
    ///
    /// To override the contents of this collection use [`set_standalone_account_rate_type_selections`](Self::set_standalone_account_rate_type_selections).
    ///
    /// <p>The updated preferred rate types for a standalone account.</p>
    pub fn standalone_account_rate_type_selections(mut self, input: crate::types::RateType) -> Self {
        let mut v = self.standalone_account_rate_type_selections.unwrap_or_default();
        v.push(input);
        self.standalone_account_rate_type_selections = ::std::option::Option::Some(v);
        self
    }
    /// <p>The updated preferred rate types for a standalone account.</p>
    pub fn set_standalone_account_rate_type_selections(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RateType>>) -> Self {
        self.standalone_account_rate_type_selections = input;
        self
    }
    /// <p>The updated preferred rate types for a standalone account.</p>
    pub fn get_standalone_account_rate_type_selections(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RateType>> {
        &self.standalone_account_rate_type_selections
    }
    /// Consumes the builder and constructs a [`UpdatePreferencesInput`](crate::operation::update_preferences::UpdatePreferencesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_preferences::UpdatePreferencesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_preferences::UpdatePreferencesInput {
            management_account_rate_type_selections: self.management_account_rate_type_selections,
            member_account_rate_type_selections: self.member_account_rate_type_selections,
            standalone_account_rate_type_selections: self.standalone_account_rate_type_selections,
        })
    }
}
