// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies a field type and keys to protect in stored web request data. This is part of the data protection configuration for a web ACL.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FieldToProtect {
    /// <p>Specifies the web request component type to protect.</p>
    pub field_type: crate::types::FieldToProtectType,
    /// <p>Specifies the keys to protect for the specified field type. If you don't specify any key, then all keys for the field type are protected.</p>
    pub field_keys: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl FieldToProtect {
    /// <p>Specifies the web request component type to protect.</p>
    pub fn field_type(&self) -> &crate::types::FieldToProtectType {
        &self.field_type
    }
    /// <p>Specifies the keys to protect for the specified field type. If you don't specify any key, then all keys for the field type are protected.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.field_keys.is_none()`.
    pub fn field_keys(&self) -> &[::std::string::String] {
        self.field_keys.as_deref().unwrap_or_default()
    }
}
impl FieldToProtect {
    /// Creates a new builder-style object to manufacture [`FieldToProtect`](crate::types::FieldToProtect).
    pub fn builder() -> crate::types::builders::FieldToProtectBuilder {
        crate::types::builders::FieldToProtectBuilder::default()
    }
}

/// A builder for [`FieldToProtect`](crate::types::FieldToProtect).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FieldToProtectBuilder {
    pub(crate) field_type: ::std::option::Option<crate::types::FieldToProtectType>,
    pub(crate) field_keys: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl FieldToProtectBuilder {
    /// <p>Specifies the web request component type to protect.</p>
    /// This field is required.
    pub fn field_type(mut self, input: crate::types::FieldToProtectType) -> Self {
        self.field_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the web request component type to protect.</p>
    pub fn set_field_type(mut self, input: ::std::option::Option<crate::types::FieldToProtectType>) -> Self {
        self.field_type = input;
        self
    }
    /// <p>Specifies the web request component type to protect.</p>
    pub fn get_field_type(&self) -> &::std::option::Option<crate::types::FieldToProtectType> {
        &self.field_type
    }
    /// Appends an item to `field_keys`.
    ///
    /// To override the contents of this collection use [`set_field_keys`](Self::set_field_keys).
    ///
    /// <p>Specifies the keys to protect for the specified field type. If you don't specify any key, then all keys for the field type are protected.</p>
    pub fn field_keys(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.field_keys.unwrap_or_default();
        v.push(input.into());
        self.field_keys = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the keys to protect for the specified field type. If you don't specify any key, then all keys for the field type are protected.</p>
    pub fn set_field_keys(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.field_keys = input;
        self
    }
    /// <p>Specifies the keys to protect for the specified field type. If you don't specify any key, then all keys for the field type are protected.</p>
    pub fn get_field_keys(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.field_keys
    }
    /// Consumes the builder and constructs a [`FieldToProtect`](crate::types::FieldToProtect).
    /// This method will fail if any of the following fields are not set:
    /// - [`field_type`](crate::types::builders::FieldToProtectBuilder::field_type)
    pub fn build(self) -> ::std::result::Result<crate::types::FieldToProtect, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FieldToProtect {
            field_type: self.field_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "field_type",
                    "field_type was not specified but it is required when building FieldToProtect",
                )
            })?,
            field_keys: self.field_keys,
        })
    }
}
