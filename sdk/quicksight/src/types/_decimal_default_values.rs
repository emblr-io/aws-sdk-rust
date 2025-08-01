// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The default values of the <code>DecimalParameterDeclaration</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DecimalDefaultValues {
    /// <p>The dynamic value of the <code>DecimalDefaultValues</code>. Different defaults are displayed according to users, groups, and values mapping.</p>
    pub dynamic_value: ::std::option::Option<crate::types::DynamicDefaultValue>,
    /// <p>The static values of the <code>DecimalDefaultValues</code>.</p>
    pub static_values: ::std::option::Option<::std::vec::Vec<f64>>,
}
impl DecimalDefaultValues {
    /// <p>The dynamic value of the <code>DecimalDefaultValues</code>. Different defaults are displayed according to users, groups, and values mapping.</p>
    pub fn dynamic_value(&self) -> ::std::option::Option<&crate::types::DynamicDefaultValue> {
        self.dynamic_value.as_ref()
    }
    /// <p>The static values of the <code>DecimalDefaultValues</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.static_values.is_none()`.
    pub fn static_values(&self) -> &[f64] {
        self.static_values.as_deref().unwrap_or_default()
    }
}
impl DecimalDefaultValues {
    /// Creates a new builder-style object to manufacture [`DecimalDefaultValues`](crate::types::DecimalDefaultValues).
    pub fn builder() -> crate::types::builders::DecimalDefaultValuesBuilder {
        crate::types::builders::DecimalDefaultValuesBuilder::default()
    }
}

/// A builder for [`DecimalDefaultValues`](crate::types::DecimalDefaultValues).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DecimalDefaultValuesBuilder {
    pub(crate) dynamic_value: ::std::option::Option<crate::types::DynamicDefaultValue>,
    pub(crate) static_values: ::std::option::Option<::std::vec::Vec<f64>>,
}
impl DecimalDefaultValuesBuilder {
    /// <p>The dynamic value of the <code>DecimalDefaultValues</code>. Different defaults are displayed according to users, groups, and values mapping.</p>
    pub fn dynamic_value(mut self, input: crate::types::DynamicDefaultValue) -> Self {
        self.dynamic_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The dynamic value of the <code>DecimalDefaultValues</code>. Different defaults are displayed according to users, groups, and values mapping.</p>
    pub fn set_dynamic_value(mut self, input: ::std::option::Option<crate::types::DynamicDefaultValue>) -> Self {
        self.dynamic_value = input;
        self
    }
    /// <p>The dynamic value of the <code>DecimalDefaultValues</code>. Different defaults are displayed according to users, groups, and values mapping.</p>
    pub fn get_dynamic_value(&self) -> &::std::option::Option<crate::types::DynamicDefaultValue> {
        &self.dynamic_value
    }
    /// Appends an item to `static_values`.
    ///
    /// To override the contents of this collection use [`set_static_values`](Self::set_static_values).
    ///
    /// <p>The static values of the <code>DecimalDefaultValues</code>.</p>
    pub fn static_values(mut self, input: f64) -> Self {
        let mut v = self.static_values.unwrap_or_default();
        v.push(input);
        self.static_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The static values of the <code>DecimalDefaultValues</code>.</p>
    pub fn set_static_values(mut self, input: ::std::option::Option<::std::vec::Vec<f64>>) -> Self {
        self.static_values = input;
        self
    }
    /// <p>The static values of the <code>DecimalDefaultValues</code>.</p>
    pub fn get_static_values(&self) -> &::std::option::Option<::std::vec::Vec<f64>> {
        &self.static_values
    }
    /// Consumes the builder and constructs a [`DecimalDefaultValues`](crate::types::DecimalDefaultValues).
    pub fn build(self) -> crate::types::DecimalDefaultValues {
        crate::types::DecimalDefaultValues {
            dynamic_value: self.dynamic_value,
            static_values: self.static_values,
        }
    }
}
