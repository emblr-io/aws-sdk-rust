// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The search criteria to be used to return security profiles.</p><note>
/// <p>The <code>name</code> field support "contains" queries with a minimum of 2 characters and maximum of 25 characters. Any queries with character lengths outside of this range will throw invalid results.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SecurityProfileSearchCriteria {
    /// <p>A list of conditions which would be applied together with an OR condition.</p>
    pub or_conditions: ::std::option::Option<::std::vec::Vec<crate::types::SecurityProfileSearchCriteria>>,
    /// <p>A list of conditions which would be applied together with an AND condition.</p>
    pub and_conditions: ::std::option::Option<::std::vec::Vec<crate::types::SecurityProfileSearchCriteria>>,
    /// <p>A leaf node condition which can be used to specify a string condition.</p>
    pub string_condition: ::std::option::Option<crate::types::StringCondition>,
}
impl SecurityProfileSearchCriteria {
    /// <p>A list of conditions which would be applied together with an OR condition.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.or_conditions.is_none()`.
    pub fn or_conditions(&self) -> &[crate::types::SecurityProfileSearchCriteria] {
        self.or_conditions.as_deref().unwrap_or_default()
    }
    /// <p>A list of conditions which would be applied together with an AND condition.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.and_conditions.is_none()`.
    pub fn and_conditions(&self) -> &[crate::types::SecurityProfileSearchCriteria] {
        self.and_conditions.as_deref().unwrap_or_default()
    }
    /// <p>A leaf node condition which can be used to specify a string condition.</p>
    pub fn string_condition(&self) -> ::std::option::Option<&crate::types::StringCondition> {
        self.string_condition.as_ref()
    }
}
impl SecurityProfileSearchCriteria {
    /// Creates a new builder-style object to manufacture [`SecurityProfileSearchCriteria`](crate::types::SecurityProfileSearchCriteria).
    pub fn builder() -> crate::types::builders::SecurityProfileSearchCriteriaBuilder {
        crate::types::builders::SecurityProfileSearchCriteriaBuilder::default()
    }
}

/// A builder for [`SecurityProfileSearchCriteria`](crate::types::SecurityProfileSearchCriteria).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SecurityProfileSearchCriteriaBuilder {
    pub(crate) or_conditions: ::std::option::Option<::std::vec::Vec<crate::types::SecurityProfileSearchCriteria>>,
    pub(crate) and_conditions: ::std::option::Option<::std::vec::Vec<crate::types::SecurityProfileSearchCriteria>>,
    pub(crate) string_condition: ::std::option::Option<crate::types::StringCondition>,
}
impl SecurityProfileSearchCriteriaBuilder {
    /// Appends an item to `or_conditions`.
    ///
    /// To override the contents of this collection use [`set_or_conditions`](Self::set_or_conditions).
    ///
    /// <p>A list of conditions which would be applied together with an OR condition.</p>
    pub fn or_conditions(mut self, input: crate::types::SecurityProfileSearchCriteria) -> Self {
        let mut v = self.or_conditions.unwrap_or_default();
        v.push(input);
        self.or_conditions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of conditions which would be applied together with an OR condition.</p>
    pub fn set_or_conditions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SecurityProfileSearchCriteria>>) -> Self {
        self.or_conditions = input;
        self
    }
    /// <p>A list of conditions which would be applied together with an OR condition.</p>
    pub fn get_or_conditions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SecurityProfileSearchCriteria>> {
        &self.or_conditions
    }
    /// Appends an item to `and_conditions`.
    ///
    /// To override the contents of this collection use [`set_and_conditions`](Self::set_and_conditions).
    ///
    /// <p>A list of conditions which would be applied together with an AND condition.</p>
    pub fn and_conditions(mut self, input: crate::types::SecurityProfileSearchCriteria) -> Self {
        let mut v = self.and_conditions.unwrap_or_default();
        v.push(input);
        self.and_conditions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of conditions which would be applied together with an AND condition.</p>
    pub fn set_and_conditions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SecurityProfileSearchCriteria>>) -> Self {
        self.and_conditions = input;
        self
    }
    /// <p>A list of conditions which would be applied together with an AND condition.</p>
    pub fn get_and_conditions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SecurityProfileSearchCriteria>> {
        &self.and_conditions
    }
    /// <p>A leaf node condition which can be used to specify a string condition.</p>
    pub fn string_condition(mut self, input: crate::types::StringCondition) -> Self {
        self.string_condition = ::std::option::Option::Some(input);
        self
    }
    /// <p>A leaf node condition which can be used to specify a string condition.</p>
    pub fn set_string_condition(mut self, input: ::std::option::Option<crate::types::StringCondition>) -> Self {
        self.string_condition = input;
        self
    }
    /// <p>A leaf node condition which can be used to specify a string condition.</p>
    pub fn get_string_condition(&self) -> &::std::option::Option<crate::types::StringCondition> {
        &self.string_condition
    }
    /// Consumes the builder and constructs a [`SecurityProfileSearchCriteria`](crate::types::SecurityProfileSearchCriteria).
    pub fn build(self) -> crate::types::SecurityProfileSearchCriteria {
        crate::types::SecurityProfileSearchCriteria {
            or_conditions: self.or_conditions,
            and_conditions: self.and_conditions,
            string_condition: self.string_condition,
        }
    }
}
