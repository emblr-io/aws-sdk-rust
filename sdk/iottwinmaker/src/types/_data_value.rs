// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that specifies a value for a property.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataValue {
    /// <p>A Boolean value.</p>
    pub boolean_value: ::std::option::Option<bool>,
    /// <p>A double value.</p>
    pub double_value: ::std::option::Option<f64>,
    /// <p>An integer value.</p>
    pub integer_value: ::std::option::Option<i32>,
    /// <p>A long value.</p>
    pub long_value: ::std::option::Option<i64>,
    /// <p>A string value.</p>
    pub string_value: ::std::option::Option<::std::string::String>,
    /// <p>A list of multiple values.</p>
    pub list_value: ::std::option::Option<::std::vec::Vec<crate::types::DataValue>>,
    /// <p>An object that maps strings to multiple <code>DataValue</code> objects.</p>
    pub map_value: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::DataValue>>,
    /// <p>A value that relates a component to another component.</p>
    pub relationship_value: ::std::option::Option<crate::types::RelationshipValue>,
    /// <p>An expression that produces the value.</p>
    pub expression: ::std::option::Option<::std::string::String>,
}
impl DataValue {
    /// <p>A Boolean value.</p>
    pub fn boolean_value(&self) -> ::std::option::Option<bool> {
        self.boolean_value
    }
    /// <p>A double value.</p>
    pub fn double_value(&self) -> ::std::option::Option<f64> {
        self.double_value
    }
    /// <p>An integer value.</p>
    pub fn integer_value(&self) -> ::std::option::Option<i32> {
        self.integer_value
    }
    /// <p>A long value.</p>
    pub fn long_value(&self) -> ::std::option::Option<i64> {
        self.long_value
    }
    /// <p>A string value.</p>
    pub fn string_value(&self) -> ::std::option::Option<&str> {
        self.string_value.as_deref()
    }
    /// <p>A list of multiple values.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.list_value.is_none()`.
    pub fn list_value(&self) -> &[crate::types::DataValue] {
        self.list_value.as_deref().unwrap_or_default()
    }
    /// <p>An object that maps strings to multiple <code>DataValue</code> objects.</p>
    pub fn map_value(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::DataValue>> {
        self.map_value.as_ref()
    }
    /// <p>A value that relates a component to another component.</p>
    pub fn relationship_value(&self) -> ::std::option::Option<&crate::types::RelationshipValue> {
        self.relationship_value.as_ref()
    }
    /// <p>An expression that produces the value.</p>
    pub fn expression(&self) -> ::std::option::Option<&str> {
        self.expression.as_deref()
    }
}
impl DataValue {
    /// Creates a new builder-style object to manufacture [`DataValue`](crate::types::DataValue).
    pub fn builder() -> crate::types::builders::DataValueBuilder {
        crate::types::builders::DataValueBuilder::default()
    }
}

/// A builder for [`DataValue`](crate::types::DataValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataValueBuilder {
    pub(crate) boolean_value: ::std::option::Option<bool>,
    pub(crate) double_value: ::std::option::Option<f64>,
    pub(crate) integer_value: ::std::option::Option<i32>,
    pub(crate) long_value: ::std::option::Option<i64>,
    pub(crate) string_value: ::std::option::Option<::std::string::String>,
    pub(crate) list_value: ::std::option::Option<::std::vec::Vec<crate::types::DataValue>>,
    pub(crate) map_value: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::DataValue>>,
    pub(crate) relationship_value: ::std::option::Option<crate::types::RelationshipValue>,
    pub(crate) expression: ::std::option::Option<::std::string::String>,
}
impl DataValueBuilder {
    /// <p>A Boolean value.</p>
    pub fn boolean_value(mut self, input: bool) -> Self {
        self.boolean_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>A Boolean value.</p>
    pub fn set_boolean_value(mut self, input: ::std::option::Option<bool>) -> Self {
        self.boolean_value = input;
        self
    }
    /// <p>A Boolean value.</p>
    pub fn get_boolean_value(&self) -> &::std::option::Option<bool> {
        &self.boolean_value
    }
    /// <p>A double value.</p>
    pub fn double_value(mut self, input: f64) -> Self {
        self.double_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>A double value.</p>
    pub fn set_double_value(mut self, input: ::std::option::Option<f64>) -> Self {
        self.double_value = input;
        self
    }
    /// <p>A double value.</p>
    pub fn get_double_value(&self) -> &::std::option::Option<f64> {
        &self.double_value
    }
    /// <p>An integer value.</p>
    pub fn integer_value(mut self, input: i32) -> Self {
        self.integer_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>An integer value.</p>
    pub fn set_integer_value(mut self, input: ::std::option::Option<i32>) -> Self {
        self.integer_value = input;
        self
    }
    /// <p>An integer value.</p>
    pub fn get_integer_value(&self) -> &::std::option::Option<i32> {
        &self.integer_value
    }
    /// <p>A long value.</p>
    pub fn long_value(mut self, input: i64) -> Self {
        self.long_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>A long value.</p>
    pub fn set_long_value(mut self, input: ::std::option::Option<i64>) -> Self {
        self.long_value = input;
        self
    }
    /// <p>A long value.</p>
    pub fn get_long_value(&self) -> &::std::option::Option<i64> {
        &self.long_value
    }
    /// <p>A string value.</p>
    pub fn string_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.string_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string value.</p>
    pub fn set_string_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.string_value = input;
        self
    }
    /// <p>A string value.</p>
    pub fn get_string_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.string_value
    }
    /// Appends an item to `list_value`.
    ///
    /// To override the contents of this collection use [`set_list_value`](Self::set_list_value).
    ///
    /// <p>A list of multiple values.</p>
    pub fn list_value(mut self, input: crate::types::DataValue) -> Self {
        let mut v = self.list_value.unwrap_or_default();
        v.push(input);
        self.list_value = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of multiple values.</p>
    pub fn set_list_value(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataValue>>) -> Self {
        self.list_value = input;
        self
    }
    /// <p>A list of multiple values.</p>
    pub fn get_list_value(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataValue>> {
        &self.list_value
    }
    /// Adds a key-value pair to `map_value`.
    ///
    /// To override the contents of this collection use [`set_map_value`](Self::set_map_value).
    ///
    /// <p>An object that maps strings to multiple <code>DataValue</code> objects.</p>
    pub fn map_value(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::DataValue) -> Self {
        let mut hash_map = self.map_value.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.map_value = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>An object that maps strings to multiple <code>DataValue</code> objects.</p>
    pub fn set_map_value(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::DataValue>>,
    ) -> Self {
        self.map_value = input;
        self
    }
    /// <p>An object that maps strings to multiple <code>DataValue</code> objects.</p>
    pub fn get_map_value(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::DataValue>> {
        &self.map_value
    }
    /// <p>A value that relates a component to another component.</p>
    pub fn relationship_value(mut self, input: crate::types::RelationshipValue) -> Self {
        self.relationship_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>A value that relates a component to another component.</p>
    pub fn set_relationship_value(mut self, input: ::std::option::Option<crate::types::RelationshipValue>) -> Self {
        self.relationship_value = input;
        self
    }
    /// <p>A value that relates a component to another component.</p>
    pub fn get_relationship_value(&self) -> &::std::option::Option<crate::types::RelationshipValue> {
        &self.relationship_value
    }
    /// <p>An expression that produces the value.</p>
    pub fn expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An expression that produces the value.</p>
    pub fn set_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expression = input;
        self
    }
    /// <p>An expression that produces the value.</p>
    pub fn get_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.expression
    }
    /// Consumes the builder and constructs a [`DataValue`](crate::types::DataValue).
    pub fn build(self) -> crate::types::DataValue {
        crate::types::DataValue {
            boolean_value: self.boolean_value,
            double_value: self.double_value,
            integer_value: self.integer_value,
            long_value: self.long_value,
            string_value: self.string_value,
            list_value: self.list_value,
            map_value: self.map_value,
            relationship_value: self.relationship_value,
            expression: self.expression,
        }
    }
}
