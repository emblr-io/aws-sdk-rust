// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateOpportunityInput {
    /// <p>Specifies the catalog associated with the request. This field takes a string value from a predefined list: <code>AWS</code> or <code>Sandbox</code>. The catalog determines which environment the opportunity is updated in. Use <code>AWS</code> to update real opportunities in the production environment, and <code>Sandbox</code> for testing in secure, isolated environments. When you use the <code>Sandbox</code> catalog, it allows you to simulate and validate your interactions with Amazon Web Services services without affecting live data or operations.</p>
    pub catalog: ::std::option::Option<::std::string::String>,
    /// <p>Identifies the type of support the partner needs from Amazon Web Services.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p>Cosell—Architectural Validation: Confirmation from Amazon Web Services that the partner's proposed solution architecture is aligned with Amazon Web Services best practices and poses minimal architectural risks.</p></li>
    /// <li>
    /// <p>Cosell—Business Presentation: Request Amazon Web Services seller's participation in a joint customer presentation.</p></li>
    /// <li>
    /// <p>Cosell—Competitive Information: Access to Amazon Web Services competitive resources and support for the partner's proposed solution.</p></li>
    /// <li>
    /// <p>Cosell—Pricing Assistance: Connect with an AWS seller for support situations where a partner may be receiving an upfront discount on a service (for example: EDP deals).</p></li>
    /// <li>
    /// <p>Cosell—Technical Consultation: Connection with an Amazon Web Services Solutions Architect to address the partner's questions about the proposed solution.</p></li>
    /// <li>
    /// <p>Cosell—Total Cost of Ownership Evaluation: Assistance with quoting different cost savings of proposed solutions on Amazon Web Services versus on-premises or a traditional hosting environment.</p></li>
    /// <li>
    /// <p>Cosell—Deal Support: Request Amazon Web Services seller's support to progress the opportunity (for example: joint customer call, strategic positioning).</p></li>
    /// <li>
    /// <p>Cosell—Support for Public Tender/RFx: Opportunity related to the public sector where the partner needs RFx support from Amazon Web Services.</p></li>
    /// </ul>
    pub primary_needs_from_aws: ::std::option::Option<::std::vec::Vec<crate::types::PrimaryNeedFromAws>>,
    /// <p>Specifies if the opportunity is associated with national security concerns. This flag is only applicable when the industry is <code>Government</code>. For national-security-related opportunities, validation and compliance rules may apply, impacting the opportunity's visibility and processing.</p>
    pub national_security: ::std::option::Option<crate::types::NationalSecurity>,
    /// <p>Specifies the opportunity's unique identifier in the partner's CRM system. This value is essential to track and reconcile because it's included in the outbound payload sent back to the partner.</p>
    pub partner_opportunity_identifier: ::std::option::Option<::std::string::String>,
    /// <p>Specifies details of the customer associated with the <code>Opportunity</code>.</p>
    pub customer: ::std::option::Option<crate::types::Customer>,
    /// <p>An object that contains project details summary for the <code>Opportunity</code>.</p>
    pub project: ::std::option::Option<crate::types::Project>,
    /// <p>Specifies the opportunity type as a renewal, new, or expansion.</p>
    /// <p>Opportunity types:</p>
    /// <ul>
    /// <li>
    /// <p>New opportunity: Represents a new business opportunity with a potential customer that's not previously engaged with your solutions or services.</p></li>
    /// <li>
    /// <p>Renewal opportunity: Represents an opportunity to renew an existing contract or subscription with a current customer, ensuring continuity of service.</p></li>
    /// <li>
    /// <p>Expansion opportunity: Represents an opportunity to expand the scope of an existing contract or subscription, either by adding new services or increasing the volume of existing services for a current customer.</p></li>
    /// </ul>
    pub opportunity_type: ::std::option::Option<crate::types::OpportunityType>,
    /// <p>An object that contains marketing details for the <code>Opportunity</code>.</p>
    pub marketing: ::std::option::Option<crate::types::Marketing>,
    /// <p>Specifies details of a customer's procurement terms. Required only for partners in eligible programs.</p>
    pub software_revenue: ::std::option::Option<crate::types::SoftwareRevenue>,
    /// <p><code>DateTime</code> when the opportunity was last modified.</p>
    pub last_modified_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Read-only, system generated <code>Opportunity</code> unique identifier.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
    /// <p>An object that contains lifecycle details for the <code>Opportunity</code>.</p>
    pub life_cycle: ::std::option::Option<crate::types::LifeCycle>,
}
impl UpdateOpportunityInput {
    /// <p>Specifies the catalog associated with the request. This field takes a string value from a predefined list: <code>AWS</code> or <code>Sandbox</code>. The catalog determines which environment the opportunity is updated in. Use <code>AWS</code> to update real opportunities in the production environment, and <code>Sandbox</code> for testing in secure, isolated environments. When you use the <code>Sandbox</code> catalog, it allows you to simulate and validate your interactions with Amazon Web Services services without affecting live data or operations.</p>
    pub fn catalog(&self) -> ::std::option::Option<&str> {
        self.catalog.as_deref()
    }
    /// <p>Identifies the type of support the partner needs from Amazon Web Services.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p>Cosell—Architectural Validation: Confirmation from Amazon Web Services that the partner's proposed solution architecture is aligned with Amazon Web Services best practices and poses minimal architectural risks.</p></li>
    /// <li>
    /// <p>Cosell—Business Presentation: Request Amazon Web Services seller's participation in a joint customer presentation.</p></li>
    /// <li>
    /// <p>Cosell—Competitive Information: Access to Amazon Web Services competitive resources and support for the partner's proposed solution.</p></li>
    /// <li>
    /// <p>Cosell—Pricing Assistance: Connect with an AWS seller for support situations where a partner may be receiving an upfront discount on a service (for example: EDP deals).</p></li>
    /// <li>
    /// <p>Cosell—Technical Consultation: Connection with an Amazon Web Services Solutions Architect to address the partner's questions about the proposed solution.</p></li>
    /// <li>
    /// <p>Cosell—Total Cost of Ownership Evaluation: Assistance with quoting different cost savings of proposed solutions on Amazon Web Services versus on-premises or a traditional hosting environment.</p></li>
    /// <li>
    /// <p>Cosell—Deal Support: Request Amazon Web Services seller's support to progress the opportunity (for example: joint customer call, strategic positioning).</p></li>
    /// <li>
    /// <p>Cosell—Support for Public Tender/RFx: Opportunity related to the public sector where the partner needs RFx support from Amazon Web Services.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.primary_needs_from_aws.is_none()`.
    pub fn primary_needs_from_aws(&self) -> &[crate::types::PrimaryNeedFromAws] {
        self.primary_needs_from_aws.as_deref().unwrap_or_default()
    }
    /// <p>Specifies if the opportunity is associated with national security concerns. This flag is only applicable when the industry is <code>Government</code>. For national-security-related opportunities, validation and compliance rules may apply, impacting the opportunity's visibility and processing.</p>
    pub fn national_security(&self) -> ::std::option::Option<&crate::types::NationalSecurity> {
        self.national_security.as_ref()
    }
    /// <p>Specifies the opportunity's unique identifier in the partner's CRM system. This value is essential to track and reconcile because it's included in the outbound payload sent back to the partner.</p>
    pub fn partner_opportunity_identifier(&self) -> ::std::option::Option<&str> {
        self.partner_opportunity_identifier.as_deref()
    }
    /// <p>Specifies details of the customer associated with the <code>Opportunity</code>.</p>
    pub fn customer(&self) -> ::std::option::Option<&crate::types::Customer> {
        self.customer.as_ref()
    }
    /// <p>An object that contains project details summary for the <code>Opportunity</code>.</p>
    pub fn project(&self) -> ::std::option::Option<&crate::types::Project> {
        self.project.as_ref()
    }
    /// <p>Specifies the opportunity type as a renewal, new, or expansion.</p>
    /// <p>Opportunity types:</p>
    /// <ul>
    /// <li>
    /// <p>New opportunity: Represents a new business opportunity with a potential customer that's not previously engaged with your solutions or services.</p></li>
    /// <li>
    /// <p>Renewal opportunity: Represents an opportunity to renew an existing contract or subscription with a current customer, ensuring continuity of service.</p></li>
    /// <li>
    /// <p>Expansion opportunity: Represents an opportunity to expand the scope of an existing contract or subscription, either by adding new services or increasing the volume of existing services for a current customer.</p></li>
    /// </ul>
    pub fn opportunity_type(&self) -> ::std::option::Option<&crate::types::OpportunityType> {
        self.opportunity_type.as_ref()
    }
    /// <p>An object that contains marketing details for the <code>Opportunity</code>.</p>
    pub fn marketing(&self) -> ::std::option::Option<&crate::types::Marketing> {
        self.marketing.as_ref()
    }
    /// <p>Specifies details of a customer's procurement terms. Required only for partners in eligible programs.</p>
    pub fn software_revenue(&self) -> ::std::option::Option<&crate::types::SoftwareRevenue> {
        self.software_revenue.as_ref()
    }
    /// <p><code>DateTime</code> when the opportunity was last modified.</p>
    pub fn last_modified_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_date.as_ref()
    }
    /// <p>Read-only, system generated <code>Opportunity</code> unique identifier.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
    /// <p>An object that contains lifecycle details for the <code>Opportunity</code>.</p>
    pub fn life_cycle(&self) -> ::std::option::Option<&crate::types::LifeCycle> {
        self.life_cycle.as_ref()
    }
}
impl UpdateOpportunityInput {
    /// Creates a new builder-style object to manufacture [`UpdateOpportunityInput`](crate::operation::update_opportunity::UpdateOpportunityInput).
    pub fn builder() -> crate::operation::update_opportunity::builders::UpdateOpportunityInputBuilder {
        crate::operation::update_opportunity::builders::UpdateOpportunityInputBuilder::default()
    }
}

/// A builder for [`UpdateOpportunityInput`](crate::operation::update_opportunity::UpdateOpportunityInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateOpportunityInputBuilder {
    pub(crate) catalog: ::std::option::Option<::std::string::String>,
    pub(crate) primary_needs_from_aws: ::std::option::Option<::std::vec::Vec<crate::types::PrimaryNeedFromAws>>,
    pub(crate) national_security: ::std::option::Option<crate::types::NationalSecurity>,
    pub(crate) partner_opportunity_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) customer: ::std::option::Option<crate::types::Customer>,
    pub(crate) project: ::std::option::Option<crate::types::Project>,
    pub(crate) opportunity_type: ::std::option::Option<crate::types::OpportunityType>,
    pub(crate) marketing: ::std::option::Option<crate::types::Marketing>,
    pub(crate) software_revenue: ::std::option::Option<crate::types::SoftwareRevenue>,
    pub(crate) last_modified_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
    pub(crate) life_cycle: ::std::option::Option<crate::types::LifeCycle>,
}
impl UpdateOpportunityInputBuilder {
    /// <p>Specifies the catalog associated with the request. This field takes a string value from a predefined list: <code>AWS</code> or <code>Sandbox</code>. The catalog determines which environment the opportunity is updated in. Use <code>AWS</code> to update real opportunities in the production environment, and <code>Sandbox</code> for testing in secure, isolated environments. When you use the <code>Sandbox</code> catalog, it allows you to simulate and validate your interactions with Amazon Web Services services without affecting live data or operations.</p>
    /// This field is required.
    pub fn catalog(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the catalog associated with the request. This field takes a string value from a predefined list: <code>AWS</code> or <code>Sandbox</code>. The catalog determines which environment the opportunity is updated in. Use <code>AWS</code> to update real opportunities in the production environment, and <code>Sandbox</code> for testing in secure, isolated environments. When you use the <code>Sandbox</code> catalog, it allows you to simulate and validate your interactions with Amazon Web Services services without affecting live data or operations.</p>
    pub fn set_catalog(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog = input;
        self
    }
    /// <p>Specifies the catalog associated with the request. This field takes a string value from a predefined list: <code>AWS</code> or <code>Sandbox</code>. The catalog determines which environment the opportunity is updated in. Use <code>AWS</code> to update real opportunities in the production environment, and <code>Sandbox</code> for testing in secure, isolated environments. When you use the <code>Sandbox</code> catalog, it allows you to simulate and validate your interactions with Amazon Web Services services without affecting live data or operations.</p>
    pub fn get_catalog(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog
    }
    /// Appends an item to `primary_needs_from_aws`.
    ///
    /// To override the contents of this collection use [`set_primary_needs_from_aws`](Self::set_primary_needs_from_aws).
    ///
    /// <p>Identifies the type of support the partner needs from Amazon Web Services.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p>Cosell—Architectural Validation: Confirmation from Amazon Web Services that the partner's proposed solution architecture is aligned with Amazon Web Services best practices and poses minimal architectural risks.</p></li>
    /// <li>
    /// <p>Cosell—Business Presentation: Request Amazon Web Services seller's participation in a joint customer presentation.</p></li>
    /// <li>
    /// <p>Cosell—Competitive Information: Access to Amazon Web Services competitive resources and support for the partner's proposed solution.</p></li>
    /// <li>
    /// <p>Cosell—Pricing Assistance: Connect with an AWS seller for support situations where a partner may be receiving an upfront discount on a service (for example: EDP deals).</p></li>
    /// <li>
    /// <p>Cosell—Technical Consultation: Connection with an Amazon Web Services Solutions Architect to address the partner's questions about the proposed solution.</p></li>
    /// <li>
    /// <p>Cosell—Total Cost of Ownership Evaluation: Assistance with quoting different cost savings of proposed solutions on Amazon Web Services versus on-premises or a traditional hosting environment.</p></li>
    /// <li>
    /// <p>Cosell—Deal Support: Request Amazon Web Services seller's support to progress the opportunity (for example: joint customer call, strategic positioning).</p></li>
    /// <li>
    /// <p>Cosell—Support for Public Tender/RFx: Opportunity related to the public sector where the partner needs RFx support from Amazon Web Services.</p></li>
    /// </ul>
    pub fn primary_needs_from_aws(mut self, input: crate::types::PrimaryNeedFromAws) -> Self {
        let mut v = self.primary_needs_from_aws.unwrap_or_default();
        v.push(input);
        self.primary_needs_from_aws = ::std::option::Option::Some(v);
        self
    }
    /// <p>Identifies the type of support the partner needs from Amazon Web Services.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p>Cosell—Architectural Validation: Confirmation from Amazon Web Services that the partner's proposed solution architecture is aligned with Amazon Web Services best practices and poses minimal architectural risks.</p></li>
    /// <li>
    /// <p>Cosell—Business Presentation: Request Amazon Web Services seller's participation in a joint customer presentation.</p></li>
    /// <li>
    /// <p>Cosell—Competitive Information: Access to Amazon Web Services competitive resources and support for the partner's proposed solution.</p></li>
    /// <li>
    /// <p>Cosell—Pricing Assistance: Connect with an AWS seller for support situations where a partner may be receiving an upfront discount on a service (for example: EDP deals).</p></li>
    /// <li>
    /// <p>Cosell—Technical Consultation: Connection with an Amazon Web Services Solutions Architect to address the partner's questions about the proposed solution.</p></li>
    /// <li>
    /// <p>Cosell—Total Cost of Ownership Evaluation: Assistance with quoting different cost savings of proposed solutions on Amazon Web Services versus on-premises or a traditional hosting environment.</p></li>
    /// <li>
    /// <p>Cosell—Deal Support: Request Amazon Web Services seller's support to progress the opportunity (for example: joint customer call, strategic positioning).</p></li>
    /// <li>
    /// <p>Cosell—Support for Public Tender/RFx: Opportunity related to the public sector where the partner needs RFx support from Amazon Web Services.</p></li>
    /// </ul>
    pub fn set_primary_needs_from_aws(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PrimaryNeedFromAws>>) -> Self {
        self.primary_needs_from_aws = input;
        self
    }
    /// <p>Identifies the type of support the partner needs from Amazon Web Services.</p>
    /// <p>Valid values:</p>
    /// <ul>
    /// <li>
    /// <p>Cosell—Architectural Validation: Confirmation from Amazon Web Services that the partner's proposed solution architecture is aligned with Amazon Web Services best practices and poses minimal architectural risks.</p></li>
    /// <li>
    /// <p>Cosell—Business Presentation: Request Amazon Web Services seller's participation in a joint customer presentation.</p></li>
    /// <li>
    /// <p>Cosell—Competitive Information: Access to Amazon Web Services competitive resources and support for the partner's proposed solution.</p></li>
    /// <li>
    /// <p>Cosell—Pricing Assistance: Connect with an AWS seller for support situations where a partner may be receiving an upfront discount on a service (for example: EDP deals).</p></li>
    /// <li>
    /// <p>Cosell—Technical Consultation: Connection with an Amazon Web Services Solutions Architect to address the partner's questions about the proposed solution.</p></li>
    /// <li>
    /// <p>Cosell—Total Cost of Ownership Evaluation: Assistance with quoting different cost savings of proposed solutions on Amazon Web Services versus on-premises or a traditional hosting environment.</p></li>
    /// <li>
    /// <p>Cosell—Deal Support: Request Amazon Web Services seller's support to progress the opportunity (for example: joint customer call, strategic positioning).</p></li>
    /// <li>
    /// <p>Cosell—Support for Public Tender/RFx: Opportunity related to the public sector where the partner needs RFx support from Amazon Web Services.</p></li>
    /// </ul>
    pub fn get_primary_needs_from_aws(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PrimaryNeedFromAws>> {
        &self.primary_needs_from_aws
    }
    /// <p>Specifies if the opportunity is associated with national security concerns. This flag is only applicable when the industry is <code>Government</code>. For national-security-related opportunities, validation and compliance rules may apply, impacting the opportunity's visibility and processing.</p>
    pub fn national_security(mut self, input: crate::types::NationalSecurity) -> Self {
        self.national_security = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies if the opportunity is associated with national security concerns. This flag is only applicable when the industry is <code>Government</code>. For national-security-related opportunities, validation and compliance rules may apply, impacting the opportunity's visibility and processing.</p>
    pub fn set_national_security(mut self, input: ::std::option::Option<crate::types::NationalSecurity>) -> Self {
        self.national_security = input;
        self
    }
    /// <p>Specifies if the opportunity is associated with national security concerns. This flag is only applicable when the industry is <code>Government</code>. For national-security-related opportunities, validation and compliance rules may apply, impacting the opportunity's visibility and processing.</p>
    pub fn get_national_security(&self) -> &::std::option::Option<crate::types::NationalSecurity> {
        &self.national_security
    }
    /// <p>Specifies the opportunity's unique identifier in the partner's CRM system. This value is essential to track and reconcile because it's included in the outbound payload sent back to the partner.</p>
    pub fn partner_opportunity_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.partner_opportunity_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the opportunity's unique identifier in the partner's CRM system. This value is essential to track and reconcile because it's included in the outbound payload sent back to the partner.</p>
    pub fn set_partner_opportunity_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.partner_opportunity_identifier = input;
        self
    }
    /// <p>Specifies the opportunity's unique identifier in the partner's CRM system. This value is essential to track and reconcile because it's included in the outbound payload sent back to the partner.</p>
    pub fn get_partner_opportunity_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.partner_opportunity_identifier
    }
    /// <p>Specifies details of the customer associated with the <code>Opportunity</code>.</p>
    pub fn customer(mut self, input: crate::types::Customer) -> Self {
        self.customer = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies details of the customer associated with the <code>Opportunity</code>.</p>
    pub fn set_customer(mut self, input: ::std::option::Option<crate::types::Customer>) -> Self {
        self.customer = input;
        self
    }
    /// <p>Specifies details of the customer associated with the <code>Opportunity</code>.</p>
    pub fn get_customer(&self) -> &::std::option::Option<crate::types::Customer> {
        &self.customer
    }
    /// <p>An object that contains project details summary for the <code>Opportunity</code>.</p>
    pub fn project(mut self, input: crate::types::Project) -> Self {
        self.project = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains project details summary for the <code>Opportunity</code>.</p>
    pub fn set_project(mut self, input: ::std::option::Option<crate::types::Project>) -> Self {
        self.project = input;
        self
    }
    /// <p>An object that contains project details summary for the <code>Opportunity</code>.</p>
    pub fn get_project(&self) -> &::std::option::Option<crate::types::Project> {
        &self.project
    }
    /// <p>Specifies the opportunity type as a renewal, new, or expansion.</p>
    /// <p>Opportunity types:</p>
    /// <ul>
    /// <li>
    /// <p>New opportunity: Represents a new business opportunity with a potential customer that's not previously engaged with your solutions or services.</p></li>
    /// <li>
    /// <p>Renewal opportunity: Represents an opportunity to renew an existing contract or subscription with a current customer, ensuring continuity of service.</p></li>
    /// <li>
    /// <p>Expansion opportunity: Represents an opportunity to expand the scope of an existing contract or subscription, either by adding new services or increasing the volume of existing services for a current customer.</p></li>
    /// </ul>
    pub fn opportunity_type(mut self, input: crate::types::OpportunityType) -> Self {
        self.opportunity_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the opportunity type as a renewal, new, or expansion.</p>
    /// <p>Opportunity types:</p>
    /// <ul>
    /// <li>
    /// <p>New opportunity: Represents a new business opportunity with a potential customer that's not previously engaged with your solutions or services.</p></li>
    /// <li>
    /// <p>Renewal opportunity: Represents an opportunity to renew an existing contract or subscription with a current customer, ensuring continuity of service.</p></li>
    /// <li>
    /// <p>Expansion opportunity: Represents an opportunity to expand the scope of an existing contract or subscription, either by adding new services or increasing the volume of existing services for a current customer.</p></li>
    /// </ul>
    pub fn set_opportunity_type(mut self, input: ::std::option::Option<crate::types::OpportunityType>) -> Self {
        self.opportunity_type = input;
        self
    }
    /// <p>Specifies the opportunity type as a renewal, new, or expansion.</p>
    /// <p>Opportunity types:</p>
    /// <ul>
    /// <li>
    /// <p>New opportunity: Represents a new business opportunity with a potential customer that's not previously engaged with your solutions or services.</p></li>
    /// <li>
    /// <p>Renewal opportunity: Represents an opportunity to renew an existing contract or subscription with a current customer, ensuring continuity of service.</p></li>
    /// <li>
    /// <p>Expansion opportunity: Represents an opportunity to expand the scope of an existing contract or subscription, either by adding new services or increasing the volume of existing services for a current customer.</p></li>
    /// </ul>
    pub fn get_opportunity_type(&self) -> &::std::option::Option<crate::types::OpportunityType> {
        &self.opportunity_type
    }
    /// <p>An object that contains marketing details for the <code>Opportunity</code>.</p>
    pub fn marketing(mut self, input: crate::types::Marketing) -> Self {
        self.marketing = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains marketing details for the <code>Opportunity</code>.</p>
    pub fn set_marketing(mut self, input: ::std::option::Option<crate::types::Marketing>) -> Self {
        self.marketing = input;
        self
    }
    /// <p>An object that contains marketing details for the <code>Opportunity</code>.</p>
    pub fn get_marketing(&self) -> &::std::option::Option<crate::types::Marketing> {
        &self.marketing
    }
    /// <p>Specifies details of a customer's procurement terms. Required only for partners in eligible programs.</p>
    pub fn software_revenue(mut self, input: crate::types::SoftwareRevenue) -> Self {
        self.software_revenue = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies details of a customer's procurement terms. Required only for partners in eligible programs.</p>
    pub fn set_software_revenue(mut self, input: ::std::option::Option<crate::types::SoftwareRevenue>) -> Self {
        self.software_revenue = input;
        self
    }
    /// <p>Specifies details of a customer's procurement terms. Required only for partners in eligible programs.</p>
    pub fn get_software_revenue(&self) -> &::std::option::Option<crate::types::SoftwareRevenue> {
        &self.software_revenue
    }
    /// <p><code>DateTime</code> when the opportunity was last modified.</p>
    /// This field is required.
    pub fn last_modified_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_date = ::std::option::Option::Some(input);
        self
    }
    /// <p><code>DateTime</code> when the opportunity was last modified.</p>
    pub fn set_last_modified_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_date = input;
        self
    }
    /// <p><code>DateTime</code> when the opportunity was last modified.</p>
    pub fn get_last_modified_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_date
    }
    /// <p>Read-only, system generated <code>Opportunity</code> unique identifier.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Read-only, system generated <code>Opportunity</code> unique identifier.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>Read-only, system generated <code>Opportunity</code> unique identifier.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// <p>An object that contains lifecycle details for the <code>Opportunity</code>.</p>
    pub fn life_cycle(mut self, input: crate::types::LifeCycle) -> Self {
        self.life_cycle = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains lifecycle details for the <code>Opportunity</code>.</p>
    pub fn set_life_cycle(mut self, input: ::std::option::Option<crate::types::LifeCycle>) -> Self {
        self.life_cycle = input;
        self
    }
    /// <p>An object that contains lifecycle details for the <code>Opportunity</code>.</p>
    pub fn get_life_cycle(&self) -> &::std::option::Option<crate::types::LifeCycle> {
        &self.life_cycle
    }
    /// Consumes the builder and constructs a [`UpdateOpportunityInput`](crate::operation::update_opportunity::UpdateOpportunityInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_opportunity::UpdateOpportunityInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_opportunity::UpdateOpportunityInput {
            catalog: self.catalog,
            primary_needs_from_aws: self.primary_needs_from_aws,
            national_security: self.national_security,
            partner_opportunity_identifier: self.partner_opportunity_identifier,
            customer: self.customer,
            project: self.project,
            opportunity_type: self.opportunity_type,
            marketing: self.marketing,
            software_revenue: self.software_revenue,
            last_modified_date: self.last_modified_date,
            identifier: self.identifier,
            life_cycle: self.life_cycle,
        })
    }
}
