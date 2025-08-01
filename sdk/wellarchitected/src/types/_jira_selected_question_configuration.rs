// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Selected questions in the workload.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct JiraSelectedQuestionConfiguration {
    /// <p>Selected pillars in the workload.</p>
    pub selected_pillars: ::std::option::Option<::std::vec::Vec<crate::types::SelectedPillar>>,
}
impl JiraSelectedQuestionConfiguration {
    /// <p>Selected pillars in the workload.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.selected_pillars.is_none()`.
    pub fn selected_pillars(&self) -> &[crate::types::SelectedPillar] {
        self.selected_pillars.as_deref().unwrap_or_default()
    }
}
impl JiraSelectedQuestionConfiguration {
    /// Creates a new builder-style object to manufacture [`JiraSelectedQuestionConfiguration`](crate::types::JiraSelectedQuestionConfiguration).
    pub fn builder() -> crate::types::builders::JiraSelectedQuestionConfigurationBuilder {
        crate::types::builders::JiraSelectedQuestionConfigurationBuilder::default()
    }
}

/// A builder for [`JiraSelectedQuestionConfiguration`](crate::types::JiraSelectedQuestionConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct JiraSelectedQuestionConfigurationBuilder {
    pub(crate) selected_pillars: ::std::option::Option<::std::vec::Vec<crate::types::SelectedPillar>>,
}
impl JiraSelectedQuestionConfigurationBuilder {
    /// Appends an item to `selected_pillars`.
    ///
    /// To override the contents of this collection use [`set_selected_pillars`](Self::set_selected_pillars).
    ///
    /// <p>Selected pillars in the workload.</p>
    pub fn selected_pillars(mut self, input: crate::types::SelectedPillar) -> Self {
        let mut v = self.selected_pillars.unwrap_or_default();
        v.push(input);
        self.selected_pillars = ::std::option::Option::Some(v);
        self
    }
    /// <p>Selected pillars in the workload.</p>
    pub fn set_selected_pillars(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SelectedPillar>>) -> Self {
        self.selected_pillars = input;
        self
    }
    /// <p>Selected pillars in the workload.</p>
    pub fn get_selected_pillars(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SelectedPillar>> {
        &self.selected_pillars
    }
    /// Consumes the builder and constructs a [`JiraSelectedQuestionConfiguration`](crate::types::JiraSelectedQuestionConfiguration).
    pub fn build(self) -> crate::types::JiraSelectedQuestionConfiguration {
        crate::types::JiraSelectedQuestionConfiguration {
            selected_pillars: self.selected_pillars,
        }
    }
}
