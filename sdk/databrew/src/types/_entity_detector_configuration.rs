// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration of entity detection for a profile job. When undefined, entity detection is disabled.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EntityDetectorConfiguration {
    /// <p>Entity types to detect. Can be any of the following:</p>
    /// <ul>
    /// <li>
    /// <p>USA_SSN</p></li>
    /// <li>
    /// <p>EMAIL</p></li>
    /// <li>
    /// <p>USA_ITIN</p></li>
    /// <li>
    /// <p>USA_PASSPORT_NUMBER</p></li>
    /// <li>
    /// <p>PHONE_NUMBER</p></li>
    /// <li>
    /// <p>USA_DRIVING_LICENSE</p></li>
    /// <li>
    /// <p>BANK_ACCOUNT</p></li>
    /// <li>
    /// <p>CREDIT_CARD</p></li>
    /// <li>
    /// <p>IP_ADDRESS</p></li>
    /// <li>
    /// <p>MAC_ADDRESS</p></li>
    /// <li>
    /// <p>USA_DEA_NUMBER</p></li>
    /// <li>
    /// <p>USA_HCPCS_CODE</p></li>
    /// <li>
    /// <p>USA_NATIONAL_PROVIDER_IDENTIFIER</p></li>
    /// <li>
    /// <p>USA_NATIONAL_DRUG_CODE</p></li>
    /// <li>
    /// <p>USA_HEALTH_INSURANCE_CLAIM_NUMBER</p></li>
    /// <li>
    /// <p>USA_MEDICARE_BENEFICIARY_IDENTIFIER</p></li>
    /// <li>
    /// <p>USA_CPT_CODE</p></li>
    /// <li>
    /// <p>PERSON_NAME</p></li>
    /// <li>
    /// <p>DATE</p></li>
    /// </ul>
    /// <p>The Entity type group USA_ALL is also supported, and includes all of the above entity types except PERSON_NAME and DATE.</p>
    pub entity_types: ::std::vec::Vec<::std::string::String>,
    /// <p>Configuration of statistics that are allowed to be run on columns that contain detected entities. When undefined, no statistics will be computed on columns that contain detected entities.</p>
    pub allowed_statistics: ::std::option::Option<::std::vec::Vec<crate::types::AllowedStatistics>>,
}
impl EntityDetectorConfiguration {
    /// <p>Entity types to detect. Can be any of the following:</p>
    /// <ul>
    /// <li>
    /// <p>USA_SSN</p></li>
    /// <li>
    /// <p>EMAIL</p></li>
    /// <li>
    /// <p>USA_ITIN</p></li>
    /// <li>
    /// <p>USA_PASSPORT_NUMBER</p></li>
    /// <li>
    /// <p>PHONE_NUMBER</p></li>
    /// <li>
    /// <p>USA_DRIVING_LICENSE</p></li>
    /// <li>
    /// <p>BANK_ACCOUNT</p></li>
    /// <li>
    /// <p>CREDIT_CARD</p></li>
    /// <li>
    /// <p>IP_ADDRESS</p></li>
    /// <li>
    /// <p>MAC_ADDRESS</p></li>
    /// <li>
    /// <p>USA_DEA_NUMBER</p></li>
    /// <li>
    /// <p>USA_HCPCS_CODE</p></li>
    /// <li>
    /// <p>USA_NATIONAL_PROVIDER_IDENTIFIER</p></li>
    /// <li>
    /// <p>USA_NATIONAL_DRUG_CODE</p></li>
    /// <li>
    /// <p>USA_HEALTH_INSURANCE_CLAIM_NUMBER</p></li>
    /// <li>
    /// <p>USA_MEDICARE_BENEFICIARY_IDENTIFIER</p></li>
    /// <li>
    /// <p>USA_CPT_CODE</p></li>
    /// <li>
    /// <p>PERSON_NAME</p></li>
    /// <li>
    /// <p>DATE</p></li>
    /// </ul>
    /// <p>The Entity type group USA_ALL is also supported, and includes all of the above entity types except PERSON_NAME and DATE.</p>
    pub fn entity_types(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.entity_types.deref()
    }
    /// <p>Configuration of statistics that are allowed to be run on columns that contain detected entities. When undefined, no statistics will be computed on columns that contain detected entities.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.allowed_statistics.is_none()`.
    pub fn allowed_statistics(&self) -> &[crate::types::AllowedStatistics] {
        self.allowed_statistics.as_deref().unwrap_or_default()
    }
}
impl EntityDetectorConfiguration {
    /// Creates a new builder-style object to manufacture [`EntityDetectorConfiguration`](crate::types::EntityDetectorConfiguration).
    pub fn builder() -> crate::types::builders::EntityDetectorConfigurationBuilder {
        crate::types::builders::EntityDetectorConfigurationBuilder::default()
    }
}

/// A builder for [`EntityDetectorConfiguration`](crate::types::EntityDetectorConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EntityDetectorConfigurationBuilder {
    pub(crate) entity_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) allowed_statistics: ::std::option::Option<::std::vec::Vec<crate::types::AllowedStatistics>>,
}
impl EntityDetectorConfigurationBuilder {
    /// Appends an item to `entity_types`.
    ///
    /// To override the contents of this collection use [`set_entity_types`](Self::set_entity_types).
    ///
    /// <p>Entity types to detect. Can be any of the following:</p>
    /// <ul>
    /// <li>
    /// <p>USA_SSN</p></li>
    /// <li>
    /// <p>EMAIL</p></li>
    /// <li>
    /// <p>USA_ITIN</p></li>
    /// <li>
    /// <p>USA_PASSPORT_NUMBER</p></li>
    /// <li>
    /// <p>PHONE_NUMBER</p></li>
    /// <li>
    /// <p>USA_DRIVING_LICENSE</p></li>
    /// <li>
    /// <p>BANK_ACCOUNT</p></li>
    /// <li>
    /// <p>CREDIT_CARD</p></li>
    /// <li>
    /// <p>IP_ADDRESS</p></li>
    /// <li>
    /// <p>MAC_ADDRESS</p></li>
    /// <li>
    /// <p>USA_DEA_NUMBER</p></li>
    /// <li>
    /// <p>USA_HCPCS_CODE</p></li>
    /// <li>
    /// <p>USA_NATIONAL_PROVIDER_IDENTIFIER</p></li>
    /// <li>
    /// <p>USA_NATIONAL_DRUG_CODE</p></li>
    /// <li>
    /// <p>USA_HEALTH_INSURANCE_CLAIM_NUMBER</p></li>
    /// <li>
    /// <p>USA_MEDICARE_BENEFICIARY_IDENTIFIER</p></li>
    /// <li>
    /// <p>USA_CPT_CODE</p></li>
    /// <li>
    /// <p>PERSON_NAME</p></li>
    /// <li>
    /// <p>DATE</p></li>
    /// </ul>
    /// <p>The Entity type group USA_ALL is also supported, and includes all of the above entity types except PERSON_NAME and DATE.</p>
    pub fn entity_types(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.entity_types.unwrap_or_default();
        v.push(input.into());
        self.entity_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>Entity types to detect. Can be any of the following:</p>
    /// <ul>
    /// <li>
    /// <p>USA_SSN</p></li>
    /// <li>
    /// <p>EMAIL</p></li>
    /// <li>
    /// <p>USA_ITIN</p></li>
    /// <li>
    /// <p>USA_PASSPORT_NUMBER</p></li>
    /// <li>
    /// <p>PHONE_NUMBER</p></li>
    /// <li>
    /// <p>USA_DRIVING_LICENSE</p></li>
    /// <li>
    /// <p>BANK_ACCOUNT</p></li>
    /// <li>
    /// <p>CREDIT_CARD</p></li>
    /// <li>
    /// <p>IP_ADDRESS</p></li>
    /// <li>
    /// <p>MAC_ADDRESS</p></li>
    /// <li>
    /// <p>USA_DEA_NUMBER</p></li>
    /// <li>
    /// <p>USA_HCPCS_CODE</p></li>
    /// <li>
    /// <p>USA_NATIONAL_PROVIDER_IDENTIFIER</p></li>
    /// <li>
    /// <p>USA_NATIONAL_DRUG_CODE</p></li>
    /// <li>
    /// <p>USA_HEALTH_INSURANCE_CLAIM_NUMBER</p></li>
    /// <li>
    /// <p>USA_MEDICARE_BENEFICIARY_IDENTIFIER</p></li>
    /// <li>
    /// <p>USA_CPT_CODE</p></li>
    /// <li>
    /// <p>PERSON_NAME</p></li>
    /// <li>
    /// <p>DATE</p></li>
    /// </ul>
    /// <p>The Entity type group USA_ALL is also supported, and includes all of the above entity types except PERSON_NAME and DATE.</p>
    pub fn set_entity_types(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.entity_types = input;
        self
    }
    /// <p>Entity types to detect. Can be any of the following:</p>
    /// <ul>
    /// <li>
    /// <p>USA_SSN</p></li>
    /// <li>
    /// <p>EMAIL</p></li>
    /// <li>
    /// <p>USA_ITIN</p></li>
    /// <li>
    /// <p>USA_PASSPORT_NUMBER</p></li>
    /// <li>
    /// <p>PHONE_NUMBER</p></li>
    /// <li>
    /// <p>USA_DRIVING_LICENSE</p></li>
    /// <li>
    /// <p>BANK_ACCOUNT</p></li>
    /// <li>
    /// <p>CREDIT_CARD</p></li>
    /// <li>
    /// <p>IP_ADDRESS</p></li>
    /// <li>
    /// <p>MAC_ADDRESS</p></li>
    /// <li>
    /// <p>USA_DEA_NUMBER</p></li>
    /// <li>
    /// <p>USA_HCPCS_CODE</p></li>
    /// <li>
    /// <p>USA_NATIONAL_PROVIDER_IDENTIFIER</p></li>
    /// <li>
    /// <p>USA_NATIONAL_DRUG_CODE</p></li>
    /// <li>
    /// <p>USA_HEALTH_INSURANCE_CLAIM_NUMBER</p></li>
    /// <li>
    /// <p>USA_MEDICARE_BENEFICIARY_IDENTIFIER</p></li>
    /// <li>
    /// <p>USA_CPT_CODE</p></li>
    /// <li>
    /// <p>PERSON_NAME</p></li>
    /// <li>
    /// <p>DATE</p></li>
    /// </ul>
    /// <p>The Entity type group USA_ALL is also supported, and includes all of the above entity types except PERSON_NAME and DATE.</p>
    pub fn get_entity_types(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.entity_types
    }
    /// Appends an item to `allowed_statistics`.
    ///
    /// To override the contents of this collection use [`set_allowed_statistics`](Self::set_allowed_statistics).
    ///
    /// <p>Configuration of statistics that are allowed to be run on columns that contain detected entities. When undefined, no statistics will be computed on columns that contain detected entities.</p>
    pub fn allowed_statistics(mut self, input: crate::types::AllowedStatistics) -> Self {
        let mut v = self.allowed_statistics.unwrap_or_default();
        v.push(input);
        self.allowed_statistics = ::std::option::Option::Some(v);
        self
    }
    /// <p>Configuration of statistics that are allowed to be run on columns that contain detected entities. When undefined, no statistics will be computed on columns that contain detected entities.</p>
    pub fn set_allowed_statistics(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AllowedStatistics>>) -> Self {
        self.allowed_statistics = input;
        self
    }
    /// <p>Configuration of statistics that are allowed to be run on columns that contain detected entities. When undefined, no statistics will be computed on columns that contain detected entities.</p>
    pub fn get_allowed_statistics(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AllowedStatistics>> {
        &self.allowed_statistics
    }
    /// Consumes the builder and constructs a [`EntityDetectorConfiguration`](crate::types::EntityDetectorConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`entity_types`](crate::types::builders::EntityDetectorConfigurationBuilder::entity_types)
    pub fn build(self) -> ::std::result::Result<crate::types::EntityDetectorConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::EntityDetectorConfiguration {
            entity_types: self.entity_types.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "entity_types",
                    "entity_types was not specified but it is required when building EntityDetectorConfiguration",
                )
            })?,
            allowed_statistics: self.allowed_statistics,
        })
    }
}
