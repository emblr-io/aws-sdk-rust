// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateOpportunityInput {
    /// <p>Specifies the catalog associated with the request. This field takes a string value from a predefined list: <code>AWS</code> or <code>Sandbox</code>. The catalog determines which environment the opportunity association is made in. Use <code>AWS</code> to associate opportunities in the Amazon Web Services catalog, and <code>Sandbox</code> for testing in secure, isolated environments.</p>
    pub catalog: ::std::option::Option<::std::string::String>,
    /// <p>Requires the <code>Opportunity</code>'s unique identifier when you want to associate it with a related entity. Provide the correct identifier so the intended opportunity is updated with the association.</p>
    pub opportunity_identifier: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the entity type that you're associating with the <code> Opportunity</code>. This helps to categorize and properly process the association.</p>
    pub related_entity_type: ::std::option::Option<crate::types::RelatedEntityType>,
    /// <p>Requires the related entity's unique identifier when you want to associate it with the <code> Opportunity</code>. For Amazon Web Services Marketplace entities, provide the Amazon Resource Name (ARN). Use the <a href="https://docs.aws.amazon.com/marketplace-catalog/latest/api-reference/welcome.html"> Amazon Web Services Marketplace API</a> to obtain the ARN.</p>
    pub related_entity_identifier: ::std::option::Option<::std::string::String>,
}
impl AssociateOpportunityInput {
    /// <p>Specifies the catalog associated with the request. This field takes a string value from a predefined list: <code>AWS</code> or <code>Sandbox</code>. The catalog determines which environment the opportunity association is made in. Use <code>AWS</code> to associate opportunities in the Amazon Web Services catalog, and <code>Sandbox</code> for testing in secure, isolated environments.</p>
    pub fn catalog(&self) -> ::std::option::Option<&str> {
        self.catalog.as_deref()
    }
    /// <p>Requires the <code>Opportunity</code>'s unique identifier when you want to associate it with a related entity. Provide the correct identifier so the intended opportunity is updated with the association.</p>
    pub fn opportunity_identifier(&self) -> ::std::option::Option<&str> {
        self.opportunity_identifier.as_deref()
    }
    /// <p>Specifies the entity type that you're associating with the <code> Opportunity</code>. This helps to categorize and properly process the association.</p>
    pub fn related_entity_type(&self) -> ::std::option::Option<&crate::types::RelatedEntityType> {
        self.related_entity_type.as_ref()
    }
    /// <p>Requires the related entity's unique identifier when you want to associate it with the <code> Opportunity</code>. For Amazon Web Services Marketplace entities, provide the Amazon Resource Name (ARN). Use the <a href="https://docs.aws.amazon.com/marketplace-catalog/latest/api-reference/welcome.html"> Amazon Web Services Marketplace API</a> to obtain the ARN.</p>
    pub fn related_entity_identifier(&self) -> ::std::option::Option<&str> {
        self.related_entity_identifier.as_deref()
    }
}
impl AssociateOpportunityInput {
    /// Creates a new builder-style object to manufacture [`AssociateOpportunityInput`](crate::operation::associate_opportunity::AssociateOpportunityInput).
    pub fn builder() -> crate::operation::associate_opportunity::builders::AssociateOpportunityInputBuilder {
        crate::operation::associate_opportunity::builders::AssociateOpportunityInputBuilder::default()
    }
}

/// A builder for [`AssociateOpportunityInput`](crate::operation::associate_opportunity::AssociateOpportunityInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateOpportunityInputBuilder {
    pub(crate) catalog: ::std::option::Option<::std::string::String>,
    pub(crate) opportunity_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) related_entity_type: ::std::option::Option<crate::types::RelatedEntityType>,
    pub(crate) related_entity_identifier: ::std::option::Option<::std::string::String>,
}
impl AssociateOpportunityInputBuilder {
    /// <p>Specifies the catalog associated with the request. This field takes a string value from a predefined list: <code>AWS</code> or <code>Sandbox</code>. The catalog determines which environment the opportunity association is made in. Use <code>AWS</code> to associate opportunities in the Amazon Web Services catalog, and <code>Sandbox</code> for testing in secure, isolated environments.</p>
    /// This field is required.
    pub fn catalog(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the catalog associated with the request. This field takes a string value from a predefined list: <code>AWS</code> or <code>Sandbox</code>. The catalog determines which environment the opportunity association is made in. Use <code>AWS</code> to associate opportunities in the Amazon Web Services catalog, and <code>Sandbox</code> for testing in secure, isolated environments.</p>
    pub fn set_catalog(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog = input;
        self
    }
    /// <p>Specifies the catalog associated with the request. This field takes a string value from a predefined list: <code>AWS</code> or <code>Sandbox</code>. The catalog determines which environment the opportunity association is made in. Use <code>AWS</code> to associate opportunities in the Amazon Web Services catalog, and <code>Sandbox</code> for testing in secure, isolated environments.</p>
    pub fn get_catalog(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog
    }
    /// <p>Requires the <code>Opportunity</code>'s unique identifier when you want to associate it with a related entity. Provide the correct identifier so the intended opportunity is updated with the association.</p>
    /// This field is required.
    pub fn opportunity_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.opportunity_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Requires the <code>Opportunity</code>'s unique identifier when you want to associate it with a related entity. Provide the correct identifier so the intended opportunity is updated with the association.</p>
    pub fn set_opportunity_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.opportunity_identifier = input;
        self
    }
    /// <p>Requires the <code>Opportunity</code>'s unique identifier when you want to associate it with a related entity. Provide the correct identifier so the intended opportunity is updated with the association.</p>
    pub fn get_opportunity_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.opportunity_identifier
    }
    /// <p>Specifies the entity type that you're associating with the <code> Opportunity</code>. This helps to categorize and properly process the association.</p>
    /// This field is required.
    pub fn related_entity_type(mut self, input: crate::types::RelatedEntityType) -> Self {
        self.related_entity_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the entity type that you're associating with the <code> Opportunity</code>. This helps to categorize and properly process the association.</p>
    pub fn set_related_entity_type(mut self, input: ::std::option::Option<crate::types::RelatedEntityType>) -> Self {
        self.related_entity_type = input;
        self
    }
    /// <p>Specifies the entity type that you're associating with the <code> Opportunity</code>. This helps to categorize and properly process the association.</p>
    pub fn get_related_entity_type(&self) -> &::std::option::Option<crate::types::RelatedEntityType> {
        &self.related_entity_type
    }
    /// <p>Requires the related entity's unique identifier when you want to associate it with the <code> Opportunity</code>. For Amazon Web Services Marketplace entities, provide the Amazon Resource Name (ARN). Use the <a href="https://docs.aws.amazon.com/marketplace-catalog/latest/api-reference/welcome.html"> Amazon Web Services Marketplace API</a> to obtain the ARN.</p>
    /// This field is required.
    pub fn related_entity_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.related_entity_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Requires the related entity's unique identifier when you want to associate it with the <code> Opportunity</code>. For Amazon Web Services Marketplace entities, provide the Amazon Resource Name (ARN). Use the <a href="https://docs.aws.amazon.com/marketplace-catalog/latest/api-reference/welcome.html"> Amazon Web Services Marketplace API</a> to obtain the ARN.</p>
    pub fn set_related_entity_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.related_entity_identifier = input;
        self
    }
    /// <p>Requires the related entity's unique identifier when you want to associate it with the <code> Opportunity</code>. For Amazon Web Services Marketplace entities, provide the Amazon Resource Name (ARN). Use the <a href="https://docs.aws.amazon.com/marketplace-catalog/latest/api-reference/welcome.html"> Amazon Web Services Marketplace API</a> to obtain the ARN.</p>
    pub fn get_related_entity_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.related_entity_identifier
    }
    /// Consumes the builder and constructs a [`AssociateOpportunityInput`](crate::operation::associate_opportunity::AssociateOpportunityInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::associate_opportunity::AssociateOpportunityInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::associate_opportunity::AssociateOpportunityInput {
            catalog: self.catalog,
            opportunity_identifier: self.opportunity_identifier,
            related_entity_type: self.related_entity_type,
            related_entity_identifier: self.related_entity_identifier,
        })
    }
}
