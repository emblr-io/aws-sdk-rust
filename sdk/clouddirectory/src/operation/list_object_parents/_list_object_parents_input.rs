// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListObjectParentsInput {
    /// <p>The Amazon Resource Name (ARN) that is associated with the <code>Directory</code> where the object resides. For more information, see <code>arns</code>.</p>
    pub directory_arn: ::std::option::Option<::std::string::String>,
    /// <p>The reference that identifies the object for which parent objects are being listed.</p>
    pub object_reference: ::std::option::Option<crate::types::ObjectReference>,
    /// <p>The pagination token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of items to be retrieved in a single call. This is an approximate number.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Represents the manner and timing in which the successful write or update of an object is reflected in a subsequent read operation of that same object.</p>
    pub consistency_level: ::std::option::Option<crate::types::ConsistencyLevel>,
    /// <p>When set to True, returns all <code>ListObjectParentsResponse$ParentLinks</code>. There could be multiple links between a parent-child pair.</p>
    pub include_all_links_to_each_parent: ::std::option::Option<bool>,
}
impl ListObjectParentsInput {
    /// <p>The Amazon Resource Name (ARN) that is associated with the <code>Directory</code> where the object resides. For more information, see <code>arns</code>.</p>
    pub fn directory_arn(&self) -> ::std::option::Option<&str> {
        self.directory_arn.as_deref()
    }
    /// <p>The reference that identifies the object for which parent objects are being listed.</p>
    pub fn object_reference(&self) -> ::std::option::Option<&crate::types::ObjectReference> {
        self.object_reference.as_ref()
    }
    /// <p>The pagination token.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of items to be retrieved in a single call. This is an approximate number.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Represents the manner and timing in which the successful write or update of an object is reflected in a subsequent read operation of that same object.</p>
    pub fn consistency_level(&self) -> ::std::option::Option<&crate::types::ConsistencyLevel> {
        self.consistency_level.as_ref()
    }
    /// <p>When set to True, returns all <code>ListObjectParentsResponse$ParentLinks</code>. There could be multiple links between a parent-child pair.</p>
    pub fn include_all_links_to_each_parent(&self) -> ::std::option::Option<bool> {
        self.include_all_links_to_each_parent
    }
}
impl ListObjectParentsInput {
    /// Creates a new builder-style object to manufacture [`ListObjectParentsInput`](crate::operation::list_object_parents::ListObjectParentsInput).
    pub fn builder() -> crate::operation::list_object_parents::builders::ListObjectParentsInputBuilder {
        crate::operation::list_object_parents::builders::ListObjectParentsInputBuilder::default()
    }
}

/// A builder for [`ListObjectParentsInput`](crate::operation::list_object_parents::ListObjectParentsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListObjectParentsInputBuilder {
    pub(crate) directory_arn: ::std::option::Option<::std::string::String>,
    pub(crate) object_reference: ::std::option::Option<crate::types::ObjectReference>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) consistency_level: ::std::option::Option<crate::types::ConsistencyLevel>,
    pub(crate) include_all_links_to_each_parent: ::std::option::Option<bool>,
}
impl ListObjectParentsInputBuilder {
    /// <p>The Amazon Resource Name (ARN) that is associated with the <code>Directory</code> where the object resides. For more information, see <code>arns</code>.</p>
    /// This field is required.
    pub fn directory_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.directory_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that is associated with the <code>Directory</code> where the object resides. For more information, see <code>arns</code>.</p>
    pub fn set_directory_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.directory_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that is associated with the <code>Directory</code> where the object resides. For more information, see <code>arns</code>.</p>
    pub fn get_directory_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.directory_arn
    }
    /// <p>The reference that identifies the object for which parent objects are being listed.</p>
    /// This field is required.
    pub fn object_reference(mut self, input: crate::types::ObjectReference) -> Self {
        self.object_reference = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reference that identifies the object for which parent objects are being listed.</p>
    pub fn set_object_reference(mut self, input: ::std::option::Option<crate::types::ObjectReference>) -> Self {
        self.object_reference = input;
        self
    }
    /// <p>The reference that identifies the object for which parent objects are being listed.</p>
    pub fn get_object_reference(&self) -> &::std::option::Option<crate::types::ObjectReference> {
        &self.object_reference
    }
    /// <p>The pagination token.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of items to be retrieved in a single call. This is an approximate number.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to be retrieved in a single call. This is an approximate number.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of items to be retrieved in a single call. This is an approximate number.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>Represents the manner and timing in which the successful write or update of an object is reflected in a subsequent read operation of that same object.</p>
    pub fn consistency_level(mut self, input: crate::types::ConsistencyLevel) -> Self {
        self.consistency_level = ::std::option::Option::Some(input);
        self
    }
    /// <p>Represents the manner and timing in which the successful write or update of an object is reflected in a subsequent read operation of that same object.</p>
    pub fn set_consistency_level(mut self, input: ::std::option::Option<crate::types::ConsistencyLevel>) -> Self {
        self.consistency_level = input;
        self
    }
    /// <p>Represents the manner and timing in which the successful write or update of an object is reflected in a subsequent read operation of that same object.</p>
    pub fn get_consistency_level(&self) -> &::std::option::Option<crate::types::ConsistencyLevel> {
        &self.consistency_level
    }
    /// <p>When set to True, returns all <code>ListObjectParentsResponse$ParentLinks</code>. There could be multiple links between a parent-child pair.</p>
    pub fn include_all_links_to_each_parent(mut self, input: bool) -> Self {
        self.include_all_links_to_each_parent = ::std::option::Option::Some(input);
        self
    }
    /// <p>When set to True, returns all <code>ListObjectParentsResponse$ParentLinks</code>. There could be multiple links between a parent-child pair.</p>
    pub fn set_include_all_links_to_each_parent(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_all_links_to_each_parent = input;
        self
    }
    /// <p>When set to True, returns all <code>ListObjectParentsResponse$ParentLinks</code>. There could be multiple links between a parent-child pair.</p>
    pub fn get_include_all_links_to_each_parent(&self) -> &::std::option::Option<bool> {
        &self.include_all_links_to_each_parent
    }
    /// Consumes the builder and constructs a [`ListObjectParentsInput`](crate::operation::list_object_parents::ListObjectParentsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_object_parents::ListObjectParentsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_object_parents::ListObjectParentsInput {
            directory_arn: self.directory_arn,
            object_reference: self.object_reference,
            next_token: self.next_token,
            max_results: self.max_results,
            consistency_level: self.consistency_level,
            include_all_links_to_each_parent: self.include_all_links_to_each_parent,
        })
    }
}
