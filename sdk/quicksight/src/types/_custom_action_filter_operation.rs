// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The filter operation that filters data included in a visual or in an entire sheet.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CustomActionFilterOperation {
    /// <p>The configuration that chooses the fields to be filtered.</p>
    pub selected_fields_configuration: ::std::option::Option<crate::types::FilterOperationSelectedFieldsConfiguration>,
    /// <p>The configuration that chooses the target visuals to be filtered.</p>
    pub target_visuals_configuration: ::std::option::Option<crate::types::FilterOperationTargetVisualsConfiguration>,
}
impl CustomActionFilterOperation {
    /// <p>The configuration that chooses the fields to be filtered.</p>
    pub fn selected_fields_configuration(&self) -> ::std::option::Option<&crate::types::FilterOperationSelectedFieldsConfiguration> {
        self.selected_fields_configuration.as_ref()
    }
    /// <p>The configuration that chooses the target visuals to be filtered.</p>
    pub fn target_visuals_configuration(&self) -> ::std::option::Option<&crate::types::FilterOperationTargetVisualsConfiguration> {
        self.target_visuals_configuration.as_ref()
    }
}
impl CustomActionFilterOperation {
    /// Creates a new builder-style object to manufacture [`CustomActionFilterOperation`](crate::types::CustomActionFilterOperation).
    pub fn builder() -> crate::types::builders::CustomActionFilterOperationBuilder {
        crate::types::builders::CustomActionFilterOperationBuilder::default()
    }
}

/// A builder for [`CustomActionFilterOperation`](crate::types::CustomActionFilterOperation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CustomActionFilterOperationBuilder {
    pub(crate) selected_fields_configuration: ::std::option::Option<crate::types::FilterOperationSelectedFieldsConfiguration>,
    pub(crate) target_visuals_configuration: ::std::option::Option<crate::types::FilterOperationTargetVisualsConfiguration>,
}
impl CustomActionFilterOperationBuilder {
    /// <p>The configuration that chooses the fields to be filtered.</p>
    /// This field is required.
    pub fn selected_fields_configuration(mut self, input: crate::types::FilterOperationSelectedFieldsConfiguration) -> Self {
        self.selected_fields_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration that chooses the fields to be filtered.</p>
    pub fn set_selected_fields_configuration(
        mut self,
        input: ::std::option::Option<crate::types::FilterOperationSelectedFieldsConfiguration>,
    ) -> Self {
        self.selected_fields_configuration = input;
        self
    }
    /// <p>The configuration that chooses the fields to be filtered.</p>
    pub fn get_selected_fields_configuration(&self) -> &::std::option::Option<crate::types::FilterOperationSelectedFieldsConfiguration> {
        &self.selected_fields_configuration
    }
    /// <p>The configuration that chooses the target visuals to be filtered.</p>
    /// This field is required.
    pub fn target_visuals_configuration(mut self, input: crate::types::FilterOperationTargetVisualsConfiguration) -> Self {
        self.target_visuals_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration that chooses the target visuals to be filtered.</p>
    pub fn set_target_visuals_configuration(mut self, input: ::std::option::Option<crate::types::FilterOperationTargetVisualsConfiguration>) -> Self {
        self.target_visuals_configuration = input;
        self
    }
    /// <p>The configuration that chooses the target visuals to be filtered.</p>
    pub fn get_target_visuals_configuration(&self) -> &::std::option::Option<crate::types::FilterOperationTargetVisualsConfiguration> {
        &self.target_visuals_configuration
    }
    /// Consumes the builder and constructs a [`CustomActionFilterOperation`](crate::types::CustomActionFilterOperation).
    pub fn build(self) -> crate::types::CustomActionFilterOperation {
        crate::types::CustomActionFilterOperation {
            selected_fields_configuration: self.selected_fields_configuration,
            target_visuals_configuration: self.target_visuals_configuration,
        }
    }
}
