// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The search criteria to be used to return users.</p><note>
/// <p>The <code>name</code> and <code>description</code> fields support "contains" queries with a minimum of 2 characters and a maximum of 25 characters. Any queries with character lengths outside of this range will throw invalid results.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UserSearchCriteria {
    /// <p>A list of conditions which would be applied together with an <code>OR</code> condition.</p>
    pub or_conditions: ::std::option::Option<::std::vec::Vec<crate::types::UserSearchCriteria>>,
    /// <p>A list of conditions which would be applied together with an <code>AND</code> condition.</p>
    pub and_conditions: ::std::option::Option<::std::vec::Vec<crate::types::UserSearchCriteria>>,
    /// <p>A leaf node condition which can be used to specify a string condition.</p>
    /// <p>The currently supported values for <code>FieldName</code> are <code>Username</code>, <code>FirstName</code>, <code>LastName</code>, <code>RoutingProfileId</code>, <code>SecurityProfileId</code>, <code>ResourceId</code>.</p>
    pub string_condition: ::std::option::Option<crate::types::StringCondition>,
    /// <p>A leaf node condition which can be used to specify a List condition to search users with attributes included in Lists like Proficiencies.</p>
    pub list_condition: ::std::option::Option<crate::types::ListCondition>,
    /// <p>A leaf node condition which can be used to specify a hierarchy group condition.</p>
    pub hierarchy_group_condition: ::std::option::Option<crate::types::HierarchyGroupCondition>,
}
impl UserSearchCriteria {
    /// <p>A list of conditions which would be applied together with an <code>OR</code> condition.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.or_conditions.is_none()`.
    pub fn or_conditions(&self) -> &[crate::types::UserSearchCriteria] {
        self.or_conditions.as_deref().unwrap_or_default()
    }
    /// <p>A list of conditions which would be applied together with an <code>AND</code> condition.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.and_conditions.is_none()`.
    pub fn and_conditions(&self) -> &[crate::types::UserSearchCriteria] {
        self.and_conditions.as_deref().unwrap_or_default()
    }
    /// <p>A leaf node condition which can be used to specify a string condition.</p>
    /// <p>The currently supported values for <code>FieldName</code> are <code>Username</code>, <code>FirstName</code>, <code>LastName</code>, <code>RoutingProfileId</code>, <code>SecurityProfileId</code>, <code>ResourceId</code>.</p>
    pub fn string_condition(&self) -> ::std::option::Option<&crate::types::StringCondition> {
        self.string_condition.as_ref()
    }
    /// <p>A leaf node condition which can be used to specify a List condition to search users with attributes included in Lists like Proficiencies.</p>
    pub fn list_condition(&self) -> ::std::option::Option<&crate::types::ListCondition> {
        self.list_condition.as_ref()
    }
    /// <p>A leaf node condition which can be used to specify a hierarchy group condition.</p>
    pub fn hierarchy_group_condition(&self) -> ::std::option::Option<&crate::types::HierarchyGroupCondition> {
        self.hierarchy_group_condition.as_ref()
    }
}
impl UserSearchCriteria {
    /// Creates a new builder-style object to manufacture [`UserSearchCriteria`](crate::types::UserSearchCriteria).
    pub fn builder() -> crate::types::builders::UserSearchCriteriaBuilder {
        crate::types::builders::UserSearchCriteriaBuilder::default()
    }
}

/// A builder for [`UserSearchCriteria`](crate::types::UserSearchCriteria).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UserSearchCriteriaBuilder {
    pub(crate) or_conditions: ::std::option::Option<::std::vec::Vec<crate::types::UserSearchCriteria>>,
    pub(crate) and_conditions: ::std::option::Option<::std::vec::Vec<crate::types::UserSearchCriteria>>,
    pub(crate) string_condition: ::std::option::Option<crate::types::StringCondition>,
    pub(crate) list_condition: ::std::option::Option<crate::types::ListCondition>,
    pub(crate) hierarchy_group_condition: ::std::option::Option<crate::types::HierarchyGroupCondition>,
}
impl UserSearchCriteriaBuilder {
    /// Appends an item to `or_conditions`.
    ///
    /// To override the contents of this collection use [`set_or_conditions`](Self::set_or_conditions).
    ///
    /// <p>A list of conditions which would be applied together with an <code>OR</code> condition.</p>
    pub fn or_conditions(mut self, input: crate::types::UserSearchCriteria) -> Self {
        let mut v = self.or_conditions.unwrap_or_default();
        v.push(input);
        self.or_conditions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of conditions which would be applied together with an <code>OR</code> condition.</p>
    pub fn set_or_conditions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UserSearchCriteria>>) -> Self {
        self.or_conditions = input;
        self
    }
    /// <p>A list of conditions which would be applied together with an <code>OR</code> condition.</p>
    pub fn get_or_conditions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UserSearchCriteria>> {
        &self.or_conditions
    }
    /// Appends an item to `and_conditions`.
    ///
    /// To override the contents of this collection use [`set_and_conditions`](Self::set_and_conditions).
    ///
    /// <p>A list of conditions which would be applied together with an <code>AND</code> condition.</p>
    pub fn and_conditions(mut self, input: crate::types::UserSearchCriteria) -> Self {
        let mut v = self.and_conditions.unwrap_or_default();
        v.push(input);
        self.and_conditions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of conditions which would be applied together with an <code>AND</code> condition.</p>
    pub fn set_and_conditions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UserSearchCriteria>>) -> Self {
        self.and_conditions = input;
        self
    }
    /// <p>A list of conditions which would be applied together with an <code>AND</code> condition.</p>
    pub fn get_and_conditions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UserSearchCriteria>> {
        &self.and_conditions
    }
    /// <p>A leaf node condition which can be used to specify a string condition.</p>
    /// <p>The currently supported values for <code>FieldName</code> are <code>Username</code>, <code>FirstName</code>, <code>LastName</code>, <code>RoutingProfileId</code>, <code>SecurityProfileId</code>, <code>ResourceId</code>.</p>
    pub fn string_condition(mut self, input: crate::types::StringCondition) -> Self {
        self.string_condition = ::std::option::Option::Some(input);
        self
    }
    /// <p>A leaf node condition which can be used to specify a string condition.</p>
    /// <p>The currently supported values for <code>FieldName</code> are <code>Username</code>, <code>FirstName</code>, <code>LastName</code>, <code>RoutingProfileId</code>, <code>SecurityProfileId</code>, <code>ResourceId</code>.</p>
    pub fn set_string_condition(mut self, input: ::std::option::Option<crate::types::StringCondition>) -> Self {
        self.string_condition = input;
        self
    }
    /// <p>A leaf node condition which can be used to specify a string condition.</p>
    /// <p>The currently supported values for <code>FieldName</code> are <code>Username</code>, <code>FirstName</code>, <code>LastName</code>, <code>RoutingProfileId</code>, <code>SecurityProfileId</code>, <code>ResourceId</code>.</p>
    pub fn get_string_condition(&self) -> &::std::option::Option<crate::types::StringCondition> {
        &self.string_condition
    }
    /// <p>A leaf node condition which can be used to specify a List condition to search users with attributes included in Lists like Proficiencies.</p>
    pub fn list_condition(mut self, input: crate::types::ListCondition) -> Self {
        self.list_condition = ::std::option::Option::Some(input);
        self
    }
    /// <p>A leaf node condition which can be used to specify a List condition to search users with attributes included in Lists like Proficiencies.</p>
    pub fn set_list_condition(mut self, input: ::std::option::Option<crate::types::ListCondition>) -> Self {
        self.list_condition = input;
        self
    }
    /// <p>A leaf node condition which can be used to specify a List condition to search users with attributes included in Lists like Proficiencies.</p>
    pub fn get_list_condition(&self) -> &::std::option::Option<crate::types::ListCondition> {
        &self.list_condition
    }
    /// <p>A leaf node condition which can be used to specify a hierarchy group condition.</p>
    pub fn hierarchy_group_condition(mut self, input: crate::types::HierarchyGroupCondition) -> Self {
        self.hierarchy_group_condition = ::std::option::Option::Some(input);
        self
    }
    /// <p>A leaf node condition which can be used to specify a hierarchy group condition.</p>
    pub fn set_hierarchy_group_condition(mut self, input: ::std::option::Option<crate::types::HierarchyGroupCondition>) -> Self {
        self.hierarchy_group_condition = input;
        self
    }
    /// <p>A leaf node condition which can be used to specify a hierarchy group condition.</p>
    pub fn get_hierarchy_group_condition(&self) -> &::std::option::Option<crate::types::HierarchyGroupCondition> {
        &self.hierarchy_group_condition
    }
    /// Consumes the builder and constructs a [`UserSearchCriteria`](crate::types::UserSearchCriteria).
    pub fn build(self) -> crate::types::UserSearchCriteria {
        crate::types::UserSearchCriteria {
            or_conditions: self.or_conditions,
            and_conditions: self.and_conditions,
            string_condition: self.string_condition,
            list_condition: self.list_condition,
            hierarchy_group_condition: self.hierarchy_group_condition,
        }
    }
}
