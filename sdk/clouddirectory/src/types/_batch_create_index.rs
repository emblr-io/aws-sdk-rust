// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Creates an index object inside of a <code>BatchRead</code> operation. For more information, see <code>CreateIndex</code> and <code>BatchReadRequest$Operations</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchCreateIndex {
    /// <p>Specifies the attributes that should be indexed on. Currently only a single attribute is supported.</p>
    pub ordered_indexed_attribute_list: ::std::vec::Vec<crate::types::AttributeKey>,
    /// <p>Indicates whether the attribute that is being indexed has unique values or not.</p>
    pub is_unique: bool,
    /// <p>A reference to the parent object that contains the index object.</p>
    pub parent_reference: ::std::option::Option<crate::types::ObjectReference>,
    /// <p>The name of the link between the parent object and the index object.</p>
    pub link_name: ::std::option::Option<::std::string::String>,
    /// <p>The batch reference name. See <a href="https://docs.aws.amazon.com/clouddirectory/latest/developerguide/transaction_support.html">Transaction Support</a> for more information.</p>
    pub batch_reference_name: ::std::option::Option<::std::string::String>,
}
impl BatchCreateIndex {
    /// <p>Specifies the attributes that should be indexed on. Currently only a single attribute is supported.</p>
    pub fn ordered_indexed_attribute_list(&self) -> &[crate::types::AttributeKey] {
        use std::ops::Deref;
        self.ordered_indexed_attribute_list.deref()
    }
    /// <p>Indicates whether the attribute that is being indexed has unique values or not.</p>
    pub fn is_unique(&self) -> bool {
        self.is_unique
    }
    /// <p>A reference to the parent object that contains the index object.</p>
    pub fn parent_reference(&self) -> ::std::option::Option<&crate::types::ObjectReference> {
        self.parent_reference.as_ref()
    }
    /// <p>The name of the link between the parent object and the index object.</p>
    pub fn link_name(&self) -> ::std::option::Option<&str> {
        self.link_name.as_deref()
    }
    /// <p>The batch reference name. See <a href="https://docs.aws.amazon.com/clouddirectory/latest/developerguide/transaction_support.html">Transaction Support</a> for more information.</p>
    pub fn batch_reference_name(&self) -> ::std::option::Option<&str> {
        self.batch_reference_name.as_deref()
    }
}
impl BatchCreateIndex {
    /// Creates a new builder-style object to manufacture [`BatchCreateIndex`](crate::types::BatchCreateIndex).
    pub fn builder() -> crate::types::builders::BatchCreateIndexBuilder {
        crate::types::builders::BatchCreateIndexBuilder::default()
    }
}

/// A builder for [`BatchCreateIndex`](crate::types::BatchCreateIndex).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchCreateIndexBuilder {
    pub(crate) ordered_indexed_attribute_list: ::std::option::Option<::std::vec::Vec<crate::types::AttributeKey>>,
    pub(crate) is_unique: ::std::option::Option<bool>,
    pub(crate) parent_reference: ::std::option::Option<crate::types::ObjectReference>,
    pub(crate) link_name: ::std::option::Option<::std::string::String>,
    pub(crate) batch_reference_name: ::std::option::Option<::std::string::String>,
}
impl BatchCreateIndexBuilder {
    /// Appends an item to `ordered_indexed_attribute_list`.
    ///
    /// To override the contents of this collection use [`set_ordered_indexed_attribute_list`](Self::set_ordered_indexed_attribute_list).
    ///
    /// <p>Specifies the attributes that should be indexed on. Currently only a single attribute is supported.</p>
    pub fn ordered_indexed_attribute_list(mut self, input: crate::types::AttributeKey) -> Self {
        let mut v = self.ordered_indexed_attribute_list.unwrap_or_default();
        v.push(input);
        self.ordered_indexed_attribute_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the attributes that should be indexed on. Currently only a single attribute is supported.</p>
    pub fn set_ordered_indexed_attribute_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AttributeKey>>) -> Self {
        self.ordered_indexed_attribute_list = input;
        self
    }
    /// <p>Specifies the attributes that should be indexed on. Currently only a single attribute is supported.</p>
    pub fn get_ordered_indexed_attribute_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AttributeKey>> {
        &self.ordered_indexed_attribute_list
    }
    /// <p>Indicates whether the attribute that is being indexed has unique values or not.</p>
    /// This field is required.
    pub fn is_unique(mut self, input: bool) -> Self {
        self.is_unique = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the attribute that is being indexed has unique values or not.</p>
    pub fn set_is_unique(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_unique = input;
        self
    }
    /// <p>Indicates whether the attribute that is being indexed has unique values or not.</p>
    pub fn get_is_unique(&self) -> &::std::option::Option<bool> {
        &self.is_unique
    }
    /// <p>A reference to the parent object that contains the index object.</p>
    pub fn parent_reference(mut self, input: crate::types::ObjectReference) -> Self {
        self.parent_reference = ::std::option::Option::Some(input);
        self
    }
    /// <p>A reference to the parent object that contains the index object.</p>
    pub fn set_parent_reference(mut self, input: ::std::option::Option<crate::types::ObjectReference>) -> Self {
        self.parent_reference = input;
        self
    }
    /// <p>A reference to the parent object that contains the index object.</p>
    pub fn get_parent_reference(&self) -> &::std::option::Option<crate::types::ObjectReference> {
        &self.parent_reference
    }
    /// <p>The name of the link between the parent object and the index object.</p>
    pub fn link_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.link_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the link between the parent object and the index object.</p>
    pub fn set_link_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.link_name = input;
        self
    }
    /// <p>The name of the link between the parent object and the index object.</p>
    pub fn get_link_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.link_name
    }
    /// <p>The batch reference name. See <a href="https://docs.aws.amazon.com/clouddirectory/latest/developerguide/transaction_support.html">Transaction Support</a> for more information.</p>
    pub fn batch_reference_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.batch_reference_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The batch reference name. See <a href="https://docs.aws.amazon.com/clouddirectory/latest/developerguide/transaction_support.html">Transaction Support</a> for more information.</p>
    pub fn set_batch_reference_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.batch_reference_name = input;
        self
    }
    /// <p>The batch reference name. See <a href="https://docs.aws.amazon.com/clouddirectory/latest/developerguide/transaction_support.html">Transaction Support</a> for more information.</p>
    pub fn get_batch_reference_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.batch_reference_name
    }
    /// Consumes the builder and constructs a [`BatchCreateIndex`](crate::types::BatchCreateIndex).
    /// This method will fail if any of the following fields are not set:
    /// - [`ordered_indexed_attribute_list`](crate::types::builders::BatchCreateIndexBuilder::ordered_indexed_attribute_list)
    pub fn build(self) -> ::std::result::Result<crate::types::BatchCreateIndex, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BatchCreateIndex {
            ordered_indexed_attribute_list: self.ordered_indexed_attribute_list.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "ordered_indexed_attribute_list",
                    "ordered_indexed_attribute_list was not specified but it is required when building BatchCreateIndex",
                )
            })?,
            is_unique: self.is_unique.unwrap_or_default(),
            parent_reference: self.parent_reference,
            link_name: self.link_name,
            batch_reference_name: self.batch_reference_name,
        })
    }
}
