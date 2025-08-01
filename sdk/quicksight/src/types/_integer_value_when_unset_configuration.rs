// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A parameter declaration for the <code>Integer</code> data type.</p>
/// <p>This is a union type structure. For this structure to be valid, only one of the attributes can be defined.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct IntegerValueWhenUnsetConfiguration {
    /// <p>The built-in options for default values. The value can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>RECOMMENDED</code>: The recommended value.</p></li>
    /// <li>
    /// <p><code>NULL</code>: The <code>NULL</code> value.</p></li>
    /// </ul>
    pub value_when_unset_option: ::std::option::Option<crate::types::ValueWhenUnsetOption>,
    /// <p>A custom value that's used when the value of a parameter isn't set.</p>
    pub custom_value: ::std::option::Option<i64>,
}
impl IntegerValueWhenUnsetConfiguration {
    /// <p>The built-in options for default values. The value can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>RECOMMENDED</code>: The recommended value.</p></li>
    /// <li>
    /// <p><code>NULL</code>: The <code>NULL</code> value.</p></li>
    /// </ul>
    pub fn value_when_unset_option(&self) -> ::std::option::Option<&crate::types::ValueWhenUnsetOption> {
        self.value_when_unset_option.as_ref()
    }
    /// <p>A custom value that's used when the value of a parameter isn't set.</p>
    pub fn custom_value(&self) -> ::std::option::Option<i64> {
        self.custom_value
    }
}
impl ::std::fmt::Debug for IntegerValueWhenUnsetConfiguration {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("IntegerValueWhenUnsetConfiguration");
        formatter.field("value_when_unset_option", &self.value_when_unset_option);
        formatter.field("custom_value", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl IntegerValueWhenUnsetConfiguration {
    /// Creates a new builder-style object to manufacture [`IntegerValueWhenUnsetConfiguration`](crate::types::IntegerValueWhenUnsetConfiguration).
    pub fn builder() -> crate::types::builders::IntegerValueWhenUnsetConfigurationBuilder {
        crate::types::builders::IntegerValueWhenUnsetConfigurationBuilder::default()
    }
}

/// A builder for [`IntegerValueWhenUnsetConfiguration`](crate::types::IntegerValueWhenUnsetConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct IntegerValueWhenUnsetConfigurationBuilder {
    pub(crate) value_when_unset_option: ::std::option::Option<crate::types::ValueWhenUnsetOption>,
    pub(crate) custom_value: ::std::option::Option<i64>,
}
impl IntegerValueWhenUnsetConfigurationBuilder {
    /// <p>The built-in options for default values. The value can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>RECOMMENDED</code>: The recommended value.</p></li>
    /// <li>
    /// <p><code>NULL</code>: The <code>NULL</code> value.</p></li>
    /// </ul>
    pub fn value_when_unset_option(mut self, input: crate::types::ValueWhenUnsetOption) -> Self {
        self.value_when_unset_option = ::std::option::Option::Some(input);
        self
    }
    /// <p>The built-in options for default values. The value can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>RECOMMENDED</code>: The recommended value.</p></li>
    /// <li>
    /// <p><code>NULL</code>: The <code>NULL</code> value.</p></li>
    /// </ul>
    pub fn set_value_when_unset_option(mut self, input: ::std::option::Option<crate::types::ValueWhenUnsetOption>) -> Self {
        self.value_when_unset_option = input;
        self
    }
    /// <p>The built-in options for default values. The value can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>RECOMMENDED</code>: The recommended value.</p></li>
    /// <li>
    /// <p><code>NULL</code>: The <code>NULL</code> value.</p></li>
    /// </ul>
    pub fn get_value_when_unset_option(&self) -> &::std::option::Option<crate::types::ValueWhenUnsetOption> {
        &self.value_when_unset_option
    }
    /// <p>A custom value that's used when the value of a parameter isn't set.</p>
    pub fn custom_value(mut self, input: i64) -> Self {
        self.custom_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>A custom value that's used when the value of a parameter isn't set.</p>
    pub fn set_custom_value(mut self, input: ::std::option::Option<i64>) -> Self {
        self.custom_value = input;
        self
    }
    /// <p>A custom value that's used when the value of a parameter isn't set.</p>
    pub fn get_custom_value(&self) -> &::std::option::Option<i64> {
        &self.custom_value
    }
    /// Consumes the builder and constructs a [`IntegerValueWhenUnsetConfiguration`](crate::types::IntegerValueWhenUnsetConfiguration).
    pub fn build(self) -> crate::types::IntegerValueWhenUnsetConfiguration {
        crate::types::IntegerValueWhenUnsetConfiguration {
            value_when_unset_option: self.value_when_unset_option,
            custom_value: self.custom_value,
        }
    }
}
impl ::std::fmt::Debug for IntegerValueWhenUnsetConfigurationBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("IntegerValueWhenUnsetConfigurationBuilder");
        formatter.field("value_when_unset_option", &self.value_when_unset_option);
        formatter.field("custom_value", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
