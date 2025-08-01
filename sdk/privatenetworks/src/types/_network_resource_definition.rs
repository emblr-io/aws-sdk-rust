// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a network resource definition.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NetworkResourceDefinition {
    /// <p>The type in the network resource definition.</p>
    pub r#type: crate::types::NetworkResourceDefinitionType,
    /// <p>The options in the network resource definition.</p>
    pub options: ::std::option::Option<::std::vec::Vec<crate::types::NameValuePair>>,
    /// <p>The count in the network resource definition.</p>
    pub count: i32,
}
impl NetworkResourceDefinition {
    /// <p>The type in the network resource definition.</p>
    pub fn r#type(&self) -> &crate::types::NetworkResourceDefinitionType {
        &self.r#type
    }
    /// <p>The options in the network resource definition.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.options.is_none()`.
    pub fn options(&self) -> &[crate::types::NameValuePair] {
        self.options.as_deref().unwrap_or_default()
    }
    /// <p>The count in the network resource definition.</p>
    pub fn count(&self) -> i32 {
        self.count
    }
}
impl NetworkResourceDefinition {
    /// Creates a new builder-style object to manufacture [`NetworkResourceDefinition`](crate::types::NetworkResourceDefinition).
    pub fn builder() -> crate::types::builders::NetworkResourceDefinitionBuilder {
        crate::types::builders::NetworkResourceDefinitionBuilder::default()
    }
}

/// A builder for [`NetworkResourceDefinition`](crate::types::NetworkResourceDefinition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NetworkResourceDefinitionBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::NetworkResourceDefinitionType>,
    pub(crate) options: ::std::option::Option<::std::vec::Vec<crate::types::NameValuePair>>,
    pub(crate) count: ::std::option::Option<i32>,
}
impl NetworkResourceDefinitionBuilder {
    /// <p>The type in the network resource definition.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::NetworkResourceDefinitionType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type in the network resource definition.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::NetworkResourceDefinitionType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type in the network resource definition.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::NetworkResourceDefinitionType> {
        &self.r#type
    }
    /// Appends an item to `options`.
    ///
    /// To override the contents of this collection use [`set_options`](Self::set_options).
    ///
    /// <p>The options in the network resource definition.</p>
    pub fn options(mut self, input: crate::types::NameValuePair) -> Self {
        let mut v = self.options.unwrap_or_default();
        v.push(input);
        self.options = ::std::option::Option::Some(v);
        self
    }
    /// <p>The options in the network resource definition.</p>
    pub fn set_options(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::NameValuePair>>) -> Self {
        self.options = input;
        self
    }
    /// <p>The options in the network resource definition.</p>
    pub fn get_options(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::NameValuePair>> {
        &self.options
    }
    /// <p>The count in the network resource definition.</p>
    /// This field is required.
    pub fn count(mut self, input: i32) -> Self {
        self.count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The count in the network resource definition.</p>
    pub fn set_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.count = input;
        self
    }
    /// <p>The count in the network resource definition.</p>
    pub fn get_count(&self) -> &::std::option::Option<i32> {
        &self.count
    }
    /// Consumes the builder and constructs a [`NetworkResourceDefinition`](crate::types::NetworkResourceDefinition).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::NetworkResourceDefinitionBuilder::type)
    /// - [`count`](crate::types::builders::NetworkResourceDefinitionBuilder::count)
    pub fn build(self) -> ::std::result::Result<crate::types::NetworkResourceDefinition, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::NetworkResourceDefinition {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building NetworkResourceDefinition",
                )
            })?,
            options: self.options,
            count: self.count.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "count",
                    "count was not specified but it is required when building NetworkResourceDefinition",
                )
            })?,
        })
    }
}
