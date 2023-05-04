import openai

openai.api_key = "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"


class BasicBlockExplorer:
    def __init__(self):
        pass

    def request_basic_block_index(self):
        while True:
            special_case = False
            bb_index_str = input(
                "\nEnter the index of the basic block to explain, or enter \"help\" to see input formats: ")
            command_list = bb_index_str.split()
            for command in command_list:
                if command.lower() == "help":
                    print("Enter the index of the basic block to have ChatGPT output the explanation to the block\n"
                          "Enter multiple indices to explain basic blocks one by one.\n"
                          "Example: 31 53 42\n"
                          "Enter \"quit\" to quit the session\n")
                    special_case = True
                    break
                elif command.lower() == "quit":
                    return command.lower()
            if not special_case:
                return command_list

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
        explanation = "\n" "Basic block " + str(bb_index) + ":\n" + response.choices[0].text.strip() + "\n"

        print(explanation)

        # Return the final explanation string
        return explanation

    def chat_interface(self, basic_blocks):
        chat_input = input("\nNow entering basic block explanation session\n"
                           "Enter the index of target basic block to receive explanation from ChatGPT\n"
                           "Enter Y/yes to proceed, type anything else to quit: ")
        if chat_input.lower() == "Y" or chat_input.lower() == "yes":
            status = True
            while status:
                valid_input = True
                commands = self.request_basic_block_index()
                for command in commands:
                    if command == "quit":
                        status = False
                        valid_input = False
                    else:
                        try:
                            index_input = int(command)
                        except ValueError:
                            print("Error: input " + command + " is not a valid index input, please enter again\n")
                            valid_input = False
                if valid_input:
                    for command in commands:
                        if int(command) < 0 or int(command) >= len(basic_blocks):
                            print("Error: index " + command + " is out of bounds. The valid index is between 0 and " +
                                  str(len(basic_blocks) - 1) + "\n")
                            break
                        else:
                            self.explain_basic_block(int(command), basic_blocks)

