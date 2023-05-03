import openai

openai.api_key = "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"


class BasicBlockExplorer:
    def __init__(self):
        pass

    def request_basic_block_index(self):
        while True:
            bb_index_str = input(
                "\nEnter the index of the basic block to explain: ")
            try:
                bb_index = int(bb_index_str)
                return bb_index
            except ValueError:
                print("Invalid index. Please enter a valid integer.")

    def explain_basic_block(self, bb_index, basic_blocks):
        # Get the basic block corresponding to the given index
        basic_block = basic_blocks[bb_index]

        # Build a string containing information about the basic block and its instructions
        prompt = f"Basic Block {bb_index}:\n"
        prompt += f"Starting Instruction: {basic_block.start_instr}\n"
        prompt += f"End Instruction: {basic_block.end_instr}\n"
        prompt += f"Next Instructions: {[instr for instr in basic_block.bb_next_instrs]}\n"
        prompt += f"Instructions: {[instr for instr in basic_block.bb_instr_list]}\n"
        prompt += "Explain this basic block in detail containing x86 instructions using the information above.\n"

        # Use the OpenAI API to generate additional explanation text
        response = openai.Completion.create(
            engine="text-davinci-003",
            prompt=prompt,
            temperature=0.5,
            max_tokens=512,
            n=1,
            stop=None,
        )
        explanation = "\n" + response.choices[0].text.strip() + "\n"

        print(explanation)

        # Return the final explanation string
        return explanation
