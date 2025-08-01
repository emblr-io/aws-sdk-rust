// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub(crate) fn access_denied_exception_correct_errors(
    mut builder: crate::types::error::builders::AccessDeniedExceptionBuilder,
) -> crate::types::error::builders::AccessDeniedExceptionBuilder {
    if builder.message.is_none() {
        builder.message = Some(Default::default())
    }
    builder
}

pub(crate) fn conflict_exception_correct_errors(
    mut builder: crate::types::error::builders::ConflictExceptionBuilder,
) -> crate::types::error::builders::ConflictExceptionBuilder {
    if builder.message.is_none() {
        builder.message = Some(Default::default())
    }
    builder
}

pub(crate) fn internal_server_exception_correct_errors(
    mut builder: crate::types::error::builders::InternalServerExceptionBuilder,
) -> crate::types::error::builders::InternalServerExceptionBuilder {
    if builder.message.is_none() {
        builder.message = Some(Default::default())
    }
    builder
}

pub(crate) fn resource_not_found_exception_correct_errors(
    mut builder: crate::types::error::builders::ResourceNotFoundExceptionBuilder,
) -> crate::types::error::builders::ResourceNotFoundExceptionBuilder {
    if builder.message.is_none() {
        builder.message = Some(Default::default())
    }
    builder
}

pub(crate) fn service_quota_exceeded_exception_correct_errors(
    mut builder: crate::types::error::builders::ServiceQuotaExceededExceptionBuilder,
) -> crate::types::error::builders::ServiceQuotaExceededExceptionBuilder {
    if builder.message.is_none() {
        builder.message = Some(Default::default())
    }
    if builder.resource_id.is_none() {
        builder.resource_id = Some(Default::default())
    }
    if builder.resource_type.is_none() {
        builder.resource_type = Some(Default::default())
    }
    if builder.service_code.is_none() {
        builder.service_code = Some(Default::default())
    }
    if builder.quota_code.is_none() {
        builder.quota_code = Some(Default::default())
    }
    builder
}

pub(crate) fn throttling_exception_correct_errors(
    mut builder: crate::types::error::builders::ThrottlingExceptionBuilder,
) -> crate::types::error::builders::ThrottlingExceptionBuilder {
    if builder.message.is_none() {
        builder.message = Some(Default::default())
    }
    builder
}

pub(crate) fn validation_exception_correct_errors(
    mut builder: crate::types::error::builders::ValidationExceptionBuilder,
) -> crate::types::error::builders::ValidationExceptionBuilder {
    if builder.message.is_none() {
        builder.message = Some(Default::default())
    }
    builder
}

pub(crate) fn create_capability_output_output_correct_errors(
    mut builder: crate::operation::create_capability::builders::CreateCapabilityOutputBuilder,
) -> crate::operation::create_capability::builders::CreateCapabilityOutputBuilder {
    if builder.capability_id.is_none() {
        builder.capability_id = Some(Default::default())
    }
    if builder.capability_arn.is_none() {
        builder.capability_arn = Some(Default::default())
    }
    if builder.name.is_none() {
        builder.name = Some(Default::default())
    }
    if builder.r#type.is_none() {
        builder.r#type = "no value was set".parse::<crate::types::CapabilityType>().ok()
    }
    if builder.configuration.is_none() {
        builder.configuration = Some(crate::types::CapabilityConfiguration::Unknown)
    }
    if builder.created_at.is_none() {
        builder.created_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    builder
}

pub(crate) fn create_partnership_output_output_correct_errors(
    mut builder: crate::operation::create_partnership::builders::CreatePartnershipOutputBuilder,
) -> crate::operation::create_partnership::builders::CreatePartnershipOutputBuilder {
    if builder.profile_id.is_none() {
        builder.profile_id = Some(Default::default())
    }
    if builder.partnership_id.is_none() {
        builder.partnership_id = Some(Default::default())
    }
    if builder.partnership_arn.is_none() {
        builder.partnership_arn = Some(Default::default())
    }
    if builder.created_at.is_none() {
        builder.created_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    builder
}

pub(crate) fn create_profile_output_output_correct_errors(
    mut builder: crate::operation::create_profile::builders::CreateProfileOutputBuilder,
) -> crate::operation::create_profile::builders::CreateProfileOutputBuilder {
    if builder.profile_id.is_none() {
        builder.profile_id = Some(Default::default())
    }
    if builder.profile_arn.is_none() {
        builder.profile_arn = Some(Default::default())
    }
    if builder.name.is_none() {
        builder.name = Some(Default::default())
    }
    if builder.business_name.is_none() {
        builder.business_name = Some(Default::default())
    }
    if builder.phone.is_none() {
        builder.phone = Some(Default::default())
    }
    if builder.created_at.is_none() {
        builder.created_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    builder
}

pub(crate) fn create_starter_mapping_template_output_output_correct_errors(
    mut builder: crate::operation::create_starter_mapping_template::builders::CreateStarterMappingTemplateOutputBuilder,
) -> crate::operation::create_starter_mapping_template::builders::CreateStarterMappingTemplateOutputBuilder {
    if builder.mapping_template.is_none() {
        builder.mapping_template = Some(Default::default())
    }
    builder
}

pub(crate) fn create_transformer_output_output_correct_errors(
    mut builder: crate::operation::create_transformer::builders::CreateTransformerOutputBuilder,
) -> crate::operation::create_transformer::builders::CreateTransformerOutputBuilder {
    if builder.transformer_id.is_none() {
        builder.transformer_id = Some(Default::default())
    }
    if builder.transformer_arn.is_none() {
        builder.transformer_arn = Some(Default::default())
    }
    if builder.name.is_none() {
        builder.name = Some(Default::default())
    }
    if builder.status.is_none() {
        builder.status = "no value was set".parse::<crate::types::TransformerStatus>().ok()
    }
    if builder.created_at.is_none() {
        builder.created_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    builder
}

pub(crate) fn generate_mapping_output_output_correct_errors(
    mut builder: crate::operation::generate_mapping::builders::GenerateMappingOutputBuilder,
) -> crate::operation::generate_mapping::builders::GenerateMappingOutputBuilder {
    if builder.mapping_template.is_none() {
        builder.mapping_template = Some(Default::default())
    }
    builder
}

pub(crate) fn get_capability_output_output_correct_errors(
    mut builder: crate::operation::get_capability::builders::GetCapabilityOutputBuilder,
) -> crate::operation::get_capability::builders::GetCapabilityOutputBuilder {
    if builder.capability_id.is_none() {
        builder.capability_id = Some(Default::default())
    }
    if builder.capability_arn.is_none() {
        builder.capability_arn = Some(Default::default())
    }
    if builder.name.is_none() {
        builder.name = Some(Default::default())
    }
    if builder.r#type.is_none() {
        builder.r#type = "no value was set".parse::<crate::types::CapabilityType>().ok()
    }
    if builder.configuration.is_none() {
        builder.configuration = Some(crate::types::CapabilityConfiguration::Unknown)
    }
    if builder.created_at.is_none() {
        builder.created_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    builder
}

pub(crate) fn get_partnership_output_output_correct_errors(
    mut builder: crate::operation::get_partnership::builders::GetPartnershipOutputBuilder,
) -> crate::operation::get_partnership::builders::GetPartnershipOutputBuilder {
    if builder.profile_id.is_none() {
        builder.profile_id = Some(Default::default())
    }
    if builder.partnership_id.is_none() {
        builder.partnership_id = Some(Default::default())
    }
    if builder.partnership_arn.is_none() {
        builder.partnership_arn = Some(Default::default())
    }
    if builder.created_at.is_none() {
        builder.created_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    builder
}

pub(crate) fn get_profile_output_output_correct_errors(
    mut builder: crate::operation::get_profile::builders::GetProfileOutputBuilder,
) -> crate::operation::get_profile::builders::GetProfileOutputBuilder {
    if builder.profile_id.is_none() {
        builder.profile_id = Some(Default::default())
    }
    if builder.profile_arn.is_none() {
        builder.profile_arn = Some(Default::default())
    }
    if builder.name.is_none() {
        builder.name = Some(Default::default())
    }
    if builder.phone.is_none() {
        builder.phone = Some(Default::default())
    }
    if builder.business_name.is_none() {
        builder.business_name = Some(Default::default())
    }
    if builder.created_at.is_none() {
        builder.created_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    builder
}

pub(crate) fn get_transformer_output_output_correct_errors(
    mut builder: crate::operation::get_transformer::builders::GetTransformerOutputBuilder,
) -> crate::operation::get_transformer::builders::GetTransformerOutputBuilder {
    if builder.transformer_id.is_none() {
        builder.transformer_id = Some(Default::default())
    }
    if builder.transformer_arn.is_none() {
        builder.transformer_arn = Some(Default::default())
    }
    if builder.name.is_none() {
        builder.name = Some(Default::default())
    }
    if builder.status.is_none() {
        builder.status = "no value was set".parse::<crate::types::TransformerStatus>().ok()
    }
    if builder.created_at.is_none() {
        builder.created_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    builder
}

pub(crate) fn get_transformer_job_output_output_correct_errors(
    mut builder: crate::operation::get_transformer_job::builders::GetTransformerJobOutputBuilder,
) -> crate::operation::get_transformer_job::builders::GetTransformerJobOutputBuilder {
    if builder.status.is_none() {
        builder.status = "no value was set".parse::<crate::types::TransformerJobStatus>().ok()
    }
    builder
}

pub(crate) fn list_capabilities_output_output_correct_errors(
    mut builder: crate::operation::list_capabilities::builders::ListCapabilitiesOutputBuilder,
) -> crate::operation::list_capabilities::builders::ListCapabilitiesOutputBuilder {
    if builder.capabilities.is_none() {
        builder.capabilities = Some(Default::default())
    }
    builder
}

pub(crate) fn list_partnerships_output_output_correct_errors(
    mut builder: crate::operation::list_partnerships::builders::ListPartnershipsOutputBuilder,
) -> crate::operation::list_partnerships::builders::ListPartnershipsOutputBuilder {
    if builder.partnerships.is_none() {
        builder.partnerships = Some(Default::default())
    }
    builder
}

pub(crate) fn list_profiles_output_output_correct_errors(
    mut builder: crate::operation::list_profiles::builders::ListProfilesOutputBuilder,
) -> crate::operation::list_profiles::builders::ListProfilesOutputBuilder {
    if builder.profiles.is_none() {
        builder.profiles = Some(Default::default())
    }
    builder
}

pub(crate) fn list_transformers_output_output_correct_errors(
    mut builder: crate::operation::list_transformers::builders::ListTransformersOutputBuilder,
) -> crate::operation::list_transformers::builders::ListTransformersOutputBuilder {
    if builder.transformers.is_none() {
        builder.transformers = Some(Default::default())
    }
    builder
}

pub(crate) fn start_transformer_job_output_output_correct_errors(
    mut builder: crate::operation::start_transformer_job::builders::StartTransformerJobOutputBuilder,
) -> crate::operation::start_transformer_job::builders::StartTransformerJobOutputBuilder {
    if builder.transformer_job_id.is_none() {
        builder.transformer_job_id = Some(Default::default())
    }
    builder
}

pub(crate) fn test_conversion_output_output_correct_errors(
    mut builder: crate::operation::test_conversion::builders::TestConversionOutputBuilder,
) -> crate::operation::test_conversion::builders::TestConversionOutputBuilder {
    if builder.converted_file_content.is_none() {
        builder.converted_file_content = Some(Default::default())
    }
    builder
}

pub(crate) fn test_mapping_output_output_correct_errors(
    mut builder: crate::operation::test_mapping::builders::TestMappingOutputBuilder,
) -> crate::operation::test_mapping::builders::TestMappingOutputBuilder {
    if builder.mapped_file_content.is_none() {
        builder.mapped_file_content = Some(Default::default())
    }
    builder
}

pub(crate) fn test_parsing_output_output_correct_errors(
    mut builder: crate::operation::test_parsing::builders::TestParsingOutputBuilder,
) -> crate::operation::test_parsing::builders::TestParsingOutputBuilder {
    if builder.parsed_file_content.is_none() {
        builder.parsed_file_content = Some(Default::default())
    }
    builder
}

pub(crate) fn update_capability_output_output_correct_errors(
    mut builder: crate::operation::update_capability::builders::UpdateCapabilityOutputBuilder,
) -> crate::operation::update_capability::builders::UpdateCapabilityOutputBuilder {
    if builder.capability_id.is_none() {
        builder.capability_id = Some(Default::default())
    }
    if builder.capability_arn.is_none() {
        builder.capability_arn = Some(Default::default())
    }
    if builder.name.is_none() {
        builder.name = Some(Default::default())
    }
    if builder.r#type.is_none() {
        builder.r#type = "no value was set".parse::<crate::types::CapabilityType>().ok()
    }
    if builder.configuration.is_none() {
        builder.configuration = Some(crate::types::CapabilityConfiguration::Unknown)
    }
    if builder.created_at.is_none() {
        builder.created_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    builder
}

pub(crate) fn update_partnership_output_output_correct_errors(
    mut builder: crate::operation::update_partnership::builders::UpdatePartnershipOutputBuilder,
) -> crate::operation::update_partnership::builders::UpdatePartnershipOutputBuilder {
    if builder.profile_id.is_none() {
        builder.profile_id = Some(Default::default())
    }
    if builder.partnership_id.is_none() {
        builder.partnership_id = Some(Default::default())
    }
    if builder.partnership_arn.is_none() {
        builder.partnership_arn = Some(Default::default())
    }
    if builder.created_at.is_none() {
        builder.created_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    builder
}

pub(crate) fn update_profile_output_output_correct_errors(
    mut builder: crate::operation::update_profile::builders::UpdateProfileOutputBuilder,
) -> crate::operation::update_profile::builders::UpdateProfileOutputBuilder {
    if builder.profile_id.is_none() {
        builder.profile_id = Some(Default::default())
    }
    if builder.profile_arn.is_none() {
        builder.profile_arn = Some(Default::default())
    }
    if builder.name.is_none() {
        builder.name = Some(Default::default())
    }
    if builder.phone.is_none() {
        builder.phone = Some(Default::default())
    }
    if builder.business_name.is_none() {
        builder.business_name = Some(Default::default())
    }
    if builder.created_at.is_none() {
        builder.created_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    builder
}

pub(crate) fn update_transformer_output_output_correct_errors(
    mut builder: crate::operation::update_transformer::builders::UpdateTransformerOutputBuilder,
) -> crate::operation::update_transformer::builders::UpdateTransformerOutputBuilder {
    if builder.transformer_id.is_none() {
        builder.transformer_id = Some(Default::default())
    }
    if builder.transformer_arn.is_none() {
        builder.transformer_arn = Some(Default::default())
    }
    if builder.name.is_none() {
        builder.name = Some(Default::default())
    }
    if builder.status.is_none() {
        builder.status = "no value was set".parse::<crate::types::TransformerStatus>().ok()
    }
    if builder.created_at.is_none() {
        builder.created_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    if builder.modified_at.is_none() {
        builder.modified_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    builder
}

pub(crate) fn input_conversion_correct_errors(
    mut builder: crate::types::builders::InputConversionBuilder,
) -> crate::types::builders::InputConversionBuilder {
    if builder.from_format.is_none() {
        builder.from_format = "no value was set".parse::<crate::types::FromFormat>().ok()
    }
    builder
}

pub(crate) fn mapping_correct_errors(mut builder: crate::types::builders::MappingBuilder) -> crate::types::builders::MappingBuilder {
    if builder.template_language.is_none() {
        builder.template_language = "no value was set".parse::<crate::types::MappingTemplateLanguage>().ok()
    }
    builder
}

pub(crate) fn output_conversion_correct_errors(
    mut builder: crate::types::builders::OutputConversionBuilder,
) -> crate::types::builders::OutputConversionBuilder {
    if builder.to_format.is_none() {
        builder.to_format = "no value was set".parse::<crate::types::ToFormat>().ok()
    }
    builder
}

pub(crate) fn sample_documents_correct_errors(
    mut builder: crate::types::builders::SampleDocumentsBuilder,
) -> crate::types::builders::SampleDocumentsBuilder {
    if builder.bucket_name.is_none() {
        builder.bucket_name = Some(Default::default())
    }
    if builder.keys.is_none() {
        builder.keys = Some(Default::default())
    }
    builder
}

pub(crate) fn capability_summary_correct_errors(
    mut builder: crate::types::builders::CapabilitySummaryBuilder,
) -> crate::types::builders::CapabilitySummaryBuilder {
    if builder.capability_id.is_none() {
        builder.capability_id = Some(Default::default())
    }
    if builder.name.is_none() {
        builder.name = Some(Default::default())
    }
    if builder.r#type.is_none() {
        builder.r#type = "no value was set".parse::<crate::types::CapabilityType>().ok()
    }
    if builder.created_at.is_none() {
        builder.created_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    builder
}

pub(crate) fn edi_configuration_correct_errors(
    mut builder: crate::types::builders::EdiConfigurationBuilder,
) -> crate::types::builders::EdiConfigurationBuilder {
    if builder.r#type.is_none() {
        builder.r#type = Some(crate::types::EdiType::Unknown)
    }
    if builder.input_location.is_none() {
        builder.input_location = {
            let builder = crate::types::builders::S3LocationBuilder::default();
            Some(builder.build())
        }
    }
    if builder.output_location.is_none() {
        builder.output_location = {
            let builder = crate::types::builders::S3LocationBuilder::default();
            Some(builder.build())
        }
    }
    if builder.transformer_id.is_none() {
        builder.transformer_id = Some(Default::default())
    }
    builder
}

pub(crate) fn partnership_summary_correct_errors(
    mut builder: crate::types::builders::PartnershipSummaryBuilder,
) -> crate::types::builders::PartnershipSummaryBuilder {
    if builder.profile_id.is_none() {
        builder.profile_id = Some(Default::default())
    }
    if builder.partnership_id.is_none() {
        builder.partnership_id = Some(Default::default())
    }
    if builder.created_at.is_none() {
        builder.created_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    builder
}

pub(crate) fn profile_summary_correct_errors(
    mut builder: crate::types::builders::ProfileSummaryBuilder,
) -> crate::types::builders::ProfileSummaryBuilder {
    if builder.profile_id.is_none() {
        builder.profile_id = Some(Default::default())
    }
    if builder.name.is_none() {
        builder.name = Some(Default::default())
    }
    if builder.business_name.is_none() {
        builder.business_name = Some(Default::default())
    }
    if builder.created_at.is_none() {
        builder.created_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    builder
}

pub(crate) fn tag_correct_errors(mut builder: crate::types::builders::TagBuilder) -> crate::types::builders::TagBuilder {
    if builder.key.is_none() {
        builder.key = Some(Default::default())
    }
    if builder.value.is_none() {
        builder.value = Some(Default::default())
    }
    builder
}

pub(crate) fn transformer_summary_correct_errors(
    mut builder: crate::types::builders::TransformerSummaryBuilder,
) -> crate::types::builders::TransformerSummaryBuilder {
    if builder.transformer_id.is_none() {
        builder.transformer_id = Some(Default::default())
    }
    if builder.name.is_none() {
        builder.name = Some(Default::default())
    }
    if builder.status.is_none() {
        builder.status = "no value was set".parse::<crate::types::TransformerStatus>().ok()
    }
    if builder.created_at.is_none() {
        builder.created_at = Some(::aws_smithy_types::DateTime::from_fractional_secs(0, 0_f64))
    }
    builder
}

pub(crate) fn wrap_options_correct_errors(mut builder: crate::types::builders::WrapOptionsBuilder) -> crate::types::builders::WrapOptionsBuilder {
    if builder.wrap_by.is_none() {
        builder.wrap_by = "no value was set".parse::<crate::types::WrapFormat>().ok()
    }
    builder
}

pub(crate) fn x12_acknowledgment_options_correct_errors(
    mut builder: crate::types::builders::X12AcknowledgmentOptionsBuilder,
) -> crate::types::builders::X12AcknowledgmentOptionsBuilder {
    if builder.functional_acknowledgment.is_none() {
        builder.functional_acknowledgment = "no value was set".parse::<crate::types::X12FunctionalAcknowledgment>().ok()
    }
    if builder.technical_acknowledgment.is_none() {
        builder.technical_acknowledgment = "no value was set".parse::<crate::types::X12TechnicalAcknowledgment>().ok()
    }
    builder
}

pub(crate) fn x12_split_options_correct_errors(
    mut builder: crate::types::builders::X12SplitOptionsBuilder,
) -> crate::types::builders::X12SplitOptionsBuilder {
    if builder.split_by.is_none() {
        builder.split_by = "no value was set".parse::<crate::types::X12SplitBy>().ok()
    }
    builder
}
