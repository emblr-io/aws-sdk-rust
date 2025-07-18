// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The value of an <code>IndexField</code> and its current status.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IndexFieldStatus {
    /// <p>Configuration information for a field in the index, including its name, type, and options. The supported options depend on the <code><code>IndexFieldType</code></code>.</p>
    pub options: ::std::option::Option<crate::types::IndexField>,
    /// <p>The status of domain configuration option.</p>
    pub status: ::std::option::Option<crate::types::OptionStatus>,
}
impl IndexFieldStatus {
    /// <p>Configuration information for a field in the index, including its name, type, and options. The supported options depend on the <code><code>IndexFieldType</code></code>.</p>
    pub fn options(&self) -> ::std::option::Option<&crate::types::IndexField> {
        self.options.as_ref()
    }
    /// <p>The status of domain configuration option.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::OptionStatus> {
        self.status.as_ref()
    }
}
impl IndexFieldStatus {
    /// Creates a new builder-style object to manufacture [`IndexFieldStatus`](crate::types::IndexFieldStatus).
    pub fn builder() -> crate::types::builders::IndexFieldStatusBuilder {
        crate::types::builders::IndexFieldStatusBuilder::default()
    }
}

/// A builder for [`IndexFieldStatus`](crate::types::IndexFieldStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IndexFieldStatusBuilder {
    pub(crate) options: ::std::option::Option<crate::types::IndexField>,
    pub(crate) status: ::std::option::Option<crate::types::OptionStatus>,
}
impl IndexFieldStatusBuilder {
    /// <p>Configuration information for a field in the index, including its name, type, and options. The supported options depend on the <code><code>IndexFieldType</code></code>.</p>
    /// This field is required.
    pub fn options(mut self, input: crate::types::IndexField) -> Self {
        self.options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration information for a field in the index, including its name, type, and options. The supported options depend on the <code><code>IndexFieldType</code></code>.</p>
    pub fn set_options(mut self, input: ::std::option::Option<crate::types::IndexField>) -> Self {
        self.options = input;
        self
    }
    /// <p>Configuration information for a field in the index, including its name, type, and options. The supported options depend on the <code><code>IndexFieldType</code></code>.</p>
    pub fn get_options(&self) -> &::std::option::Option<crate::types::IndexField> {
        &self.options
    }
    /// <p>The status of domain configuration option.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::OptionStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of domain configuration option.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::OptionStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of domain configuration option.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::OptionStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`IndexFieldStatus`](crate::types::IndexFieldStatus).
    pub fn build(self) -> crate::types::IndexFieldStatus {
        crate::types::IndexFieldStatus {
            options: self.options,
            status: self.status,
        }
    }
}
