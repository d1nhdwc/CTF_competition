// g++ -O2 chall.cpp -o chall

#include <iostream>
#include <string>
#include <sstream>

using namespace std;

const int CAP = 8;

string notes[CAP];

int main() {
    cout.setf(ios::unitbuf);

    while (true) {
        cout << "> ";
        string line;
        getline(cin, line);
        istringstream iss(line);
        string command;
        iss >> command;

        if (command == "exit")
            break;
        if (command == "put") {
            int idx;
            iss >> idx;
            string val;            
            iss >> val;
            notes[idx] = val;
        } else if (command == "get") {
            int idx;
            iss >> idx;
            cout << notes[idx] << endl;
        } else {
            cout << "unknown command" << endl;
        }
    }

    return 0;
}
