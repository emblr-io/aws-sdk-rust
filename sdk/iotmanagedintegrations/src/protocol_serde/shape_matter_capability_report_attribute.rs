// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub fn ser_matter_capability_report_attribute(
    object: &mut ::aws_smithy_json::serialize::JsonObjectWriter,
    input: &crate::types::MatterCapabilityReportAttribute,
) -> ::std::result::Result<(), ::aws_smithy_types::error::operation::SerializationError> {
    if let Some(var_1) = &input.id {
        object.key("id").string(var_1.as_str());
    }
    if let Some(var_2) = &input.name {
        object.key("name").string(var_2.as_str());
    }
    if let Some(var_3) = &input.value {
        object.key("value").document(var_3);
    }
    Ok(())
}
