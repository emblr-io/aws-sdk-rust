// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RemoveFacetFromObjectInput {
    /// <p>The ARN of the directory in which the object resides.</p>
    pub directory_arn: ::std::option::Option<::std::string::String>,
    /// <p>The facet to remove. See <code>SchemaFacet</code> for details.</p>
    pub schema_facet: ::std::option::Option<crate::types::SchemaFacet>,
    /// <p>A reference to the object to remove the facet from.</p>
    pub object_reference: ::std::option::Option<crate::types::ObjectReference>,
}
impl RemoveFacetFromObjectInput {
    /// <p>The ARN of the directory in which the object resides.</p>
    pub fn directory_arn(&self) -> ::std::option::Option<&str> {
        self.directory_arn.as_deref()
    }
    /// <p>The facet to remove. See <code>SchemaFacet</code> for details.</p>
    pub fn schema_facet(&self) -> ::std::option::Option<&crate::types::SchemaFacet> {
        self.schema_facet.as_ref()
    }
    /// <p>A reference to the object to remove the facet from.</p>
    pub fn object_reference(&self) -> ::std::option::Option<&crate::types::ObjectReference> {
        self.object_reference.as_ref()
    }
}
impl RemoveFacetFromObjectInput {
    /// Creates a new builder-style object to manufacture [`RemoveFacetFromObjectInput`](crate::operation::remove_facet_from_object::RemoveFacetFromObjectInput).
    pub fn builder() -> crate::operation::remove_facet_from_object::builders::RemoveFacetFromObjectInputBuilder {
        crate::operation::remove_facet_from_object::builders::RemoveFacetFromObjectInputBuilder::default()
    }
}

/// A builder for [`RemoveFacetFromObjectInput`](crate::operation::remove_facet_from_object::RemoveFacetFromObjectInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RemoveFacetFromObjectInputBuilder {
    pub(crate) directory_arn: ::std::option::Option<::std::string::String>,
    pub(crate) schema_facet: ::std::option::Option<crate::types::SchemaFacet>,
    pub(crate) object_reference: ::std::option::Option<crate::types::ObjectReference>,
}
impl RemoveFacetFromObjectInputBuilder {
    /// <p>The ARN of the directory in which the object resides.</p>
    /// This field is required.
    pub fn directory_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.directory_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the directory in which the object resides.</p>
    pub fn set_directory_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.directory_arn = input;
        self
    }
    /// <p>The ARN of the directory in which the object resides.</p>
    pub fn get_directory_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.directory_arn
    }
    /// <p>The facet to remove. See <code>SchemaFacet</code> for details.</p>
    /// This field is required.
    pub fn schema_facet(mut self, input: crate::types::SchemaFacet) -> Self {
        self.schema_facet = ::std::option::Option::Some(input);
        self
    }
    /// <p>The facet to remove. See <code>SchemaFacet</code> for details.</p>
    pub fn set_schema_facet(mut self, input: ::std::option::Option<crate::types::SchemaFacet>) -> Self {
        self.schema_facet = input;
        self
    }
    /// <p>The facet to remove. See <code>SchemaFacet</code> for details.</p>
    pub fn get_schema_facet(&self) -> &::std::option::Option<crate::types::SchemaFacet> {
        &self.schema_facet
    }
    /// <p>A reference to the object to remove the facet from.</p>
    /// This field is required.
    pub fn object_reference(mut self, input: crate::types::ObjectReference) -> Self {
        self.object_reference = ::std::option::Option::Some(input);
        self
    }
    /// <p>A reference to the object to remove the facet from.</p>
    pub fn set_object_reference(mut self, input: ::std::option::Option<crate::types::ObjectReference>) -> Self {
        self.object_reference = input;
        self
    }
    /// <p>A reference to the object to remove the facet from.</p>
    pub fn get_object_reference(&self) -> &::std::option::Option<crate::types::ObjectReference> {
        &self.object_reference
    }
    /// Consumes the builder and constructs a [`RemoveFacetFromObjectInput`](crate::operation::remove_facet_from_object::RemoveFacetFromObjectInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::remove_facet_from_object::RemoveFacetFromObjectInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::remove_facet_from_object::RemoveFacetFromObjectInput {
            directory_arn: self.directory_arn,
            schema_facet: self.schema_facet,
            object_reference: self.object_reference,
        })
    }
}
