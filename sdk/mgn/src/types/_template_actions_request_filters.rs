// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Template post migration custom action filters.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TemplateActionsRequestFilters {
    /// <p>Action IDs to filter template post migration custom actions by.</p>
    pub action_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl TemplateActionsRequestFilters {
    /// <p>Action IDs to filter template post migration custom actions by.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.action_ids.is_none()`.
    pub fn action_ids(&self) -> &[::std::string::String] {
        self.action_ids.as_deref().unwrap_or_default()
    }
}
impl TemplateActionsRequestFilters {
    /// Creates a new builder-style object to manufacture [`TemplateActionsRequestFilters`](crate::types::TemplateActionsRequestFilters).
    pub fn builder() -> crate::types::builders::TemplateActionsRequestFiltersBuilder {
        crate::types::builders::TemplateActionsRequestFiltersBuilder::default()
    }
}

/// A builder for [`TemplateActionsRequestFilters`](crate::types::TemplateActionsRequestFilters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TemplateActionsRequestFiltersBuilder {
    pub(crate) action_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl TemplateActionsRequestFiltersBuilder {
    /// Appends an item to `action_ids`.
    ///
    /// To override the contents of this collection use [`set_action_ids`](Self::set_action_ids).
    ///
    /// <p>Action IDs to filter template post migration custom actions by.</p>
    pub fn action_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.action_ids.unwrap_or_default();
        v.push(input.into());
        self.action_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>Action IDs to filter template post migration custom actions by.</p>
    pub fn set_action_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.action_ids = input;
        self
    }
    /// <p>Action IDs to filter template post migration custom actions by.</p>
    pub fn get_action_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.action_ids
    }
    /// Consumes the builder and constructs a [`TemplateActionsRequestFilters`](crate::types::TemplateActionsRequestFilters).
    pub fn build(self) -> crate::types::TemplateActionsRequestFilters {
        crate::types::TemplateActionsRequestFilters { action_ids: self.action_ids }
    }
}
